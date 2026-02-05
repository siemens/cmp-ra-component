package com.siemens.pki.cmpracomponent.msggeneration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.msgprocessing.StreamType;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for {@link MsgOutputProtector#stripRedundantExtraCerts(PKIMessage)}.
 *
 * <h2>Purpose</h2>
 * <p>
 * This test suite verifies the behavior of the <em>extraCerts suppression</em> logic in
 * {@link MsgOutputProtector}. When configured to suppress redundant extra certificates,
 * {@code stripRedundantExtraCerts} removes certificates that were already sent earlier in the same
 * transaction and updates the {@link PersistencyContext} to remember newly sent certificates.
 * </p>
 *
 * <h2>What is being tested</h2>
 * <ul>
 * <li>The method removes extraCerts that have already been sent (as tracked in
 * {@link PersistencyContext}).</li>
 * <li>Remaining extraCerts keep their original order.</li>
 * <li>When all extraCerts are redundant, the resulting PKIMessage has
 * {@code extraCerts == null}.</li>
 * <li>The persistency sets for "already sent certificates" are updated with the remaining
 * extras.</li>
 * <li>The logic for choosing <em>which</em> set to use depends on {@link StreamType}:
 * <ul>
 * <li><strong>Downstream</strong>: uses
 * {@link PersistencyContext#getAlreadySentExtraCertsToDownStream()}.</li>
 * <li><strong>Upstream</strong>: uses
 * {@link PersistencyContext#getAlreadySentExtraCertsToUpStream()}.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Test strategy</h2>
 * <p>
 * The tests construct minimal but valid {@link PKIMessage} instances where the body is of type
 * {@code TYPE_CONFIRM} (CMP Confirm) with {@link DERNull#INSTANCE} content. This avoids the need
 * for complex CRMF structures while remaining spec-compliant for unit testing. Each test creates
 * real {@link CMPCertificate} instances using BouncyCastle so that equality and set membership
 * behave naturally.
 * </p>
 *
 * <h2>Assumptions</h2>
 * <ul>
 * <li>{@code MsgOutputProtector} is constructed in {@code ReprotectMode.keep} with a
 * {@link SharedSecretCredentialContext}, satisfying construction requirements without needing
 * signature-based credentials.</li>
 * <li>{@code PersistencyContext} getters lazily initialize their sets and return mutable sets.</li>
 * </ul>
 *
 * <h2>Out of scope</h2>
 * <ul>
 * <li>We do not validate cryptographic semantics or end-to-end message protection creation. The
 * focus is purely on extraCerts suppression and persistency updates.</li>
 * <li>We do not test the other reprotection modes ({@code reprotect}, {@code strip}) here.</li>
 * </ul>
 */
public class TestMsgOutputProtector {

    /** Shared RSA key pair used to issue dummy X.509 certs once for all tests. */
    private static KeyPair kp;

    /** Dummy algorithm identifier set on the PKIHeader's protectionAlg for test messages. */
    private static final AlgorithmIdentifier DUMMY_ALG = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5"));

    /**
     * Generates a single RSA key pair reused by all tests to speed up certificate creation.
     */
    @BeforeClass
    public static void init() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        kp = g.generateKeyPair();
    }

    /**
     * Build a minimal {@link PKIMessage} suitable for these tests.
     * <p>
     * The body uses {@code TYPE_CONFIRM} (value 19) with {@link DERNull#INSTANCE} as content, which
     * is valid for CMP's PKIConfirmContent ::= NULL. This choice avoids constructing complex bodies
     * (e.g., CertReqMessages) not needed for testing the extraCerts suppression logic.
     * </p>
     *
     * @param extra optional list of extra certificates to include as {@code extraCerts}
     * @return a valid {@link PKIMessage} with header, body, dummy protection and optional extraCerts
     */
    private PKIMessage newMsg(CMPCertificate... extra) {
        PKIHeader hdr = new PKIHeaderBuilder(
                        PKIHeader.CMP_2000,
                        new GeneralName(new X500Name("CN=SENDER")),
                        new GeneralName(new X500Name("CN=RECIPIENT")))
                .setProtectionAlg(DUMMY_ALG)
                .build();

        // TYPE_CONFIRM accepts NULL content → perfect for minimal test bodies
        PKIBody body = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
        DERBitString prot = new DERBitString(new byte[] {1}); // non-null protection marker

        return new PKIMessage(hdr, body, prot, (extra == null || extra.length == 0) ? null : extra);
    }

    /**
     * Create a small self-signed X.509 certificate and wrap it as a {@link CMPCertificate}.
     * <p>
     * This ensures that equality and set semantics are realistic, as BouncyCastle compares ASN.1
     * structures. The content is unique enough for test scenarios by varying the subject CN and the
     * serial number.
     * </p>
     *
     * @param cn the CN for the subject and issuer DN
     * @return a {@link CMPCertificate} wrapping the ASN.1 X.509 certificate
     * @throws Exception if certificate construction fails (unlikely in test context)
     */
    private CMPCertificate cert(String cn) throws Exception {
        X500Name subject = new X500Name("CN=" + cn);
        Date nb = new Date(System.currentTimeMillis() - 1000);
        Date na = new Date(System.currentTimeMillis() + 3600000);
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        SubjectPublicKeyInfo spki =
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(subject, serial, nb, na, subject, spki);

        ContentSigner s = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        Certificate c = b.build(s).toASN1Structure();
        return new CMPCertificate(c);
    }

    /**
     * Construct a {@link MsgOutputProtector} configured for tests:
     * <ul>
     * <li>{@code ReprotectMode.keep} to ensure forwarded-protection paths are exercised.</li>
     * <li>{@code suppressRedundantExtraCerts = suppress} to toggle stripping on/off.</li>
     * <li>{@link SharedSecretCredentialContext} as the credential type (simple, no PKI setup).</li>
     * <li>Provided {@link PersistencyContext} and {@link StreamType} are injected to control
     * direction and pre-known certificates.</li>
     * </ul>
     *
     * @param suppress true to enable suppression logic; false to leave extraCerts untouched
     * @param pc persistency context used to fetch/update already sent extra certs
     * @param st stream type indicating downstream or upstream flow
     * @return a configured {@link MsgOutputProtector} ready for testing
     */
    private MsgOutputProtector protector(boolean suppress, PersistencyContext pc, StreamType st)
            throws GeneralSecurityException, CmpProcessingException {

        // Minimal config: keep-mode; enforce reprotect mode; suppression toggled by param.
        CmpMessageInterface cfg = new CmpMessageInterface() {
            @Override
            public VerificationContext getInputVerification() {
                return null;
            }

            @Override
            public NestedEndpointContext getNestedEndpointContext() {
                return null;
            }

            @Override
            public CredentialContext getOutputCredentials() {
                return null;
            }

            @Override
            public ReprotectMode getReprotectMode() {
                return ReprotectMode.keep;
            }

            @Override
            public boolean isEnforceReprotectMode() {
                return true;
            }

            @Override
            public boolean getSuppressRedundantExtraCerts() {
                return suppress;
            }

            @Override
            public boolean isCacheExtraCerts() {
                return false;
            }

            @Override
            public boolean isMessageTimeDeviationAllowed(long d) {
                return true;
            }
        };

        // Shared-secret credentials are sufficient for constructor path.
        SharedSecretCredentialContext cred = new SharedSecretCredentialContext() {
            @Override
            public byte[] getSharedSecret() {
                return "s".getBytes();
            }
        };

        MessageContext mc = new MessageContext(pc, cred);
        return new MsgOutputProtector(cfg, st, mc);
    }

    /**
     * Verifies that in a <strong>downstream</strong> message flow:
     * <ul>
     * <li>If an extraCert is already recorded in the downstream-known set, it is stripped.</li>
     * <li>Non-redundant extraCerts remain and are added to the downstream-known set.</li>
     * </ul>
     * <p>
     * Setup:
     * <ol>
     * <li>Mark certificate {@code known} as already sent downstream.</li>
     * <li>Create a message containing {@code [known, fresh]} as extraCerts.</li>
     * <li>Call {@code stripRedundantExtraCerts} and expect only {@code fresh} to remain.</li>
     * <li>Verify {@code fresh} is now recorded as sent downstream.</li>
     * </ol>
     */
    @Test
    public void downstream_partialRedundancy() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate known = cert("K");
        CMPCertificate fresh = cert("F");

        // New logic: downstream flow uses the downstream set.
        pc.getAlreadySentExtraCertsToDownStream().add(known);

        MsgOutputProtector p = protector(true, pc, StreamType.downstream("DOWN"));

        PKIMessage out = p.stripRedundantExtraCerts(newMsg(known, fresh));

        assertEquals(1, out.getExtraCerts().length); // only one extra remains
        assertSame(fresh, out.getExtraCerts()[0]); // it's the 'fresh' one
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(fresh)); // persisted
        // Verify already-known set now contains both certificates
        assertEquals(2, pc.getAlreadySentExtraCertsToDownStream().size());
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().containsAll(List.of(known, fresh)));
    }

    /**
     * Verifies that in an <strong>upstream</strong> message flow:
     * <ul>
     * <li>If an extraCert is already recorded in the upstream-known set, it is stripped.</li>
     * <li>Non-redundant extraCerts remain and are added to the upstream-known set.</li>
     * </ul>
     * <p>
     * Setup mirrors the downstream test but targets the upstream set to match
     * {@link MsgOutputProtector}'s updated logic.
     */
    @Test
    public void upstream_partialRedundancy() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate known = cert("K");
        CMPCertificate fresh = cert("F");

        // New logic: upstream flow uses the upstream set.
        pc.getAlreadySentExtraCertsToUpStream().add(known);

        MsgOutputProtector p = protector(true, pc, StreamType.upstream("UP"));

        PKIMessage out = p.stripRedundantExtraCerts(newMsg(known, fresh));

        assertEquals(1, out.getExtraCerts().length);
        assertSame(fresh, out.getExtraCerts()[0]);
        assertTrue(pc.getAlreadySentExtraCertsToUpStream().contains(fresh));
        // Verify already-known set now contains both certificates
        assertEquals(2, pc.getAlreadySentExtraCertsToUpStream().size());
        assertTrue(pc.getAlreadySentExtraCertsToUpStream().containsAll(List.of(known, fresh)));
    }

    /**
     * Verifies that if <strong>all</strong> extraCerts are already known in the downstream set, the
     * resulting message has {@code extraCerts == null}.
     * <p>
     * This tests the branch where the list becomes empty after removal, and the implementation
     * intentionally collapses {@code []} to {@code null} to save bandwidth.
     */
    @Test
    public void downstream_allRedundant() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate a = cert("A");
        pc.getAlreadySentExtraCertsToDownStream().add(a);

        MsgOutputProtector p = protector(true, pc, StreamType.downstream("DOWN"));

        PKIMessage out = p.stripRedundantExtraCerts(newMsg(a));

        assertNull(out.getExtraCerts()); // all extras were redundant → becomes null
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(a)); // original known remains
    }

    /**
     * Verifies the <strong>order is preserved</strong> for remaining non-redundant extraCerts after
     * stripping.
     * <p>
     * Setup:
     * <ol>
     * <li>Mark {@code b} as already known downstream.</li>
     * <li>Create a message with extraCerts = {@code [a, b, c]}.</li>
     * <li>After stripping, expect {@code [a, c]} in <strong>that same order</strong>.</li>
     * </ol>
     * <p>
     * Also verifies that both {@code a} and {@code c} are added to the downstream-known set.
     */
    @Test
    public void orderPreserved() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate a = cert("A");
        CMPCertificate b = cert("B");
        CMPCertificate c = cert("C");

        pc.getAlreadySentExtraCertsToDownStream().add(b);

        MsgOutputProtector p = protector(true, pc, StreamType.downstream("DOWN"));

        PKIMessage out = p.stripRedundantExtraCerts(newMsg(a, b, c));

        CMPCertificate[] x = out.getExtraCerts();
        assertEquals(2, x.length);
        assertSame(a, x[0]); // original order preserved
        assertSame(c, x[1]);

        // Persistency updated with remaining extras
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(a));
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(c));
    }
}
