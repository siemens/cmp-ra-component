package com.siemens.pki.cmpracomponent.persistency.cache.service;

import com.siemens.pki.cmpracomponent.persistency.cache.CertificateCache;
import com.siemens.pki.cmpracomponent.persistency.cache.model.CertKind;
import com.siemens.pki.cmpracomponent.persistency.cache.model.CertNode;
import com.siemens.pki.cmpracomponent.persistency.cache.model.CertificateIdentity;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory implementation of a PKI certificate hierarchy cache.
 *
 * <p>
 * Characteristics:
 * <ul>
 * <li>Order-independent (CMP-safe)</li>
 * <li>Cryptographically verified parent-child relationships</li>
 * <li>Self-healing graph as certificates arrive</li>
 * <li>No revocation or validity checking</li>
 * </ul>
 * </p>
 */
public final class InMemoryCache implements CertificateCache {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final Map<CertificateIdentity, CertNode> nodes = new ConcurrentHashMap<>();
    private final Map<ByteBuffer, CertificateIdentity> skiIndex = new ConcurrentHashMap<>();
    private static final Logger LOG = LoggerFactory.getLogger(InMemoryCache.class);

    public InMemoryCache() {}

    @Override
    public void add(CMPCertificate cmpCertificate) {

        CertificateIdentity identity = CertificateIdentity.from(cmpCertificate);
        if (nodes.containsKey(identity)) {
            return;
        }

        Certificate cert = cmpCertificate.getX509v3PKCert();
        CertKind kind = CertKind.classify(cert);

        CertNode node = new CertNode(identity, cmpCertificate, null, kind != CertKind.LEAF);
        nodes.put(identity, node);

        switch (kind) {
            case ROOT_CA:
                tryToAdoptOrphans(node);
                break;

            case INTERMEDIATE_CA:
                tryToAttachToExistingCa(node);
                tryToAdoptOrphans(node);
                break;

            case LEAF:
                tryToAttachToExistingCa(node);
                break;

            default:
                throw new AssertionError("Unhandled CertKind: " + kind);
        }
    }

    @Override
    public LinkedHashSet<CMPCertificate> getChain(CMPCertificate certificate) {

        CertificateIdentity start = CertificateIdentity.from(certificate);
        LinkedHashSet<CMPCertificate> chain = new LinkedHashSet<>();
        Set<CertificateIdentity> visited = new HashSet<>();

        CertificateIdentity current = start;
        while (current != null) {
            if (!visited.add(current)) {
                throw new IllegalStateException("Certificate cycle detected: " + current);
            }

            CertNode node = nodes.get(current);
            if (node == null || node.getCertificate() == null) {
                throw new IllegalStateException("Missing certificate data: " + current);
            }

            chain.add(node.getCertificate());
            current = node.getParent();
        }
        return chain;
    }

    @Override
    public LinkedHashSet<CMPCertificate> getChainBySKID(byte[] skid) {

        CertificateIdentity id = skiIndex.get(ByteBuffer.wrap(skid));

        if (id == null) {
            return new LinkedHashSet<>();
        }

        CertNode node = nodes.get(id);
        if (node == null) {
            return new LinkedHashSet<>();
        }

        return getChain(node.getCertificate());
    }

    @Override
    public int clean() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public void setMaxUnusedLeafDuration(Duration duration) {
        // TODO Auto-generated method stub

    }

    /* ---------------- internal helpers ---------------- */

    private void tryToAttachToExistingCa(CertNode node) {

        Certificate cert = node.getCertificate().getX509v3PKCert();

        nodes.values().stream()
                .filter(CertNode::isCA)
                .filter(ca -> ca.getCertificate().getX509v3PKCert().getSubject().equals(cert.getIssuer()))
                .filter(ca -> verifyIssuedBy(node.getCertificate(), ca.getCertificate()))
                .findFirst()
                .ifPresent(ca -> ca.addChild(node));
    }

    private void tryToAdoptOrphans(CertNode caNode) {

        Certificate caCert = caNode.getCertificate().getX509v3PKCert();

        nodes.values().stream()
                .filter(n -> n.getParent() == null)
                .filter(n -> n != caNode)
                .filter(n -> !n.isCA())
                .filter(n -> n.getCertificate().getX509v3PKCert().getIssuer().equals(caCert.getSubject()))
                .filter(n -> verifyIssuedBy(n.getCertificate(), caNode.getCertificate()))
                .forEach(orphan -> reparent(orphan, caNode));
    }

    private void reparent(CertNode orphan, CertNode parent) {
        CertNode updated = new CertNode(orphan.getKey(), orphan.getCertificate(), parent.getKey(), orphan.isCA());
        parent.addChild(updated);
        nodes.put(orphan.getKey(), updated);
    }

    private boolean verifyIssuedBy(CMPCertificate child, CMPCertificate parent) {
        try {
            X509Certificate c = toJca(child);
            X509Certificate p = toJca(parent);
            c.verify(p.getPublicKey());
            return true;
        } catch (Exception e) {
            LOG.debug("Certificate signature verification failed", e);
            return false;
        }
    }

    private X509Certificate toJca(CMPCertificate cmp) throws Exception {
        byte[] encoded = cmp.getX509v3PKCert().getEncoded();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
    }

    private ByteBuffer extractSki(CMPCertificate cert) {
        var extensions = cert.getX509v3PKCert().getTBSCertificate().getExtensions();
        if (extensions == null) return null;

        var ext = extensions.getExtension(Extension.subjectKeyIdentifier);
        if (ext == null) return null;

        byte[] ski = SubjectKeyIdentifier.getInstance(ext.getParsedValue()).getKeyIdentifier();

        return ByteBuffer.wrap(ski);
    }
}
