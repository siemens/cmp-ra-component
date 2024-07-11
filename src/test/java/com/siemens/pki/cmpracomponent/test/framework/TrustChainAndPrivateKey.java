/*
 *  Copyright (c) 2020 Siemens AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 */
package com.siemens.pki.cmpracomponent.test.framework;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;

import static com.siemens.pki.cmpracomponent.cryptoservices.ProviderWrapper.tryWithAllProviders;

public class TrustChainAndPrivateKey implements SignatureCredentialContext, VerificationContext {

    // chain starting with end certificate ending with root certificate
    private final LinkedList<X509Certificate> trustChain = new LinkedList<>();

    private final Set<X509Certificate> trustAnchors = new HashSet<>();

    private PrivateKey privateKeyOfEndCertififcate = null;

    /**
     * create a new cert chain
     *
     * @param subjectPrefix prefix fur all common names
     * @param withoutEndCert TODO
     * @param kpg           generator to use for key generation
     * @param chainLength   length from root to end to generate
     * param withoutEndCert if <code>true</code>, generate unfinished chain without end certificate
     * @throws Exception in case of error
     */
    public TrustChainAndPrivateKey(String subjectPrefix, boolean withoutEndCert, KeyPairGenerator... kpg)
            throws Exception {
        final int finalChainLength = withoutEndCert ? kpg.length + 1 : kpg.length;
        final long now = System.currentTimeMillis();
        // generate trusted root
        KeyPair rootKeypair = kpg[0].generateKeyPair();
        X500Principal lastIssuer = new X500Principal("CN=" + subjectPrefix + "_ROOT");
        PublicKey privateRootKey = rootKeypair.getPublic();
        final X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                lastIssuer,
                BigInteger.valueOf(now),
                new Date(now - 60 * 60 * 1000L),
                new Date(now + 100 * 60 * 60 * 1000L),
                lastIssuer,
                privateRootKey);
        final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3CertBldr.addExtension(
                Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(privateRootKey));
        v3CertBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(finalChainLength));
        JcaContentSignerBuilder signerBuilder = tryWithAllProviders(p -> {
            return new JcaContentSignerBuilder(AlgorithmHelper.getSigningAlgNameFromKey(rootKeypair.getPrivate()))
                    .setProvider(p);
        });
        X509Certificate lastCert = tryWithAllProviders(p -> new JcaX509CertificateConverter()
                .setProvider(p)
                .getCertificate(v3CertBldr.build(signerBuilder.build(rootKeypair.getPrivate()))));
        trustAnchors.add(lastCert);
        trustChain.addLast(lastCert);
        privateKeyOfEndCertififcate = rootKeypair.getPrivate();
        if (finalChainLength <= 1) {
            return;
        }
        if (finalChainLength == 2 && withoutEndCert) {
            return;
        }
        int certsStillToGenerate = finalChainLength - 1;
        for (int i = 1; ; i++) {
            X500Principal nextIssuer = certsStillToGenerate > 1
                    ? new X500Principal("CN=" + subjectPrefix + "_INTERMEDIATE_" + certsStillToGenerate)
                    : new X500Principal("CN=" + subjectPrefix + "_END");
            KeyPair nextKeyPair = kpg[i].generateKeyPair();
            JcaX509v3CertificateBuilder nextV3CertBldr = new JcaX509v3CertificateBuilder(
                    lastIssuer,
                    BigInteger.valueOf(now),
                    new Date(now - 60 * 60 * 1000L),
                    new Date(now + 100 * 60 * 60 * 1000L),
                    nextIssuer,
                    nextKeyPair.getPublic());
            nextV3CertBldr.addExtension(
                    Extension.subjectKeyIdentifier,
                    false,
                    extUtils.createSubjectKeyIdentifier(nextKeyPair.getPublic()));
            nextV3CertBldr.addExtension(
                    Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(lastCert));
            nextV3CertBldr.addExtension(
                    Extension.basicConstraints,
                    true,
                    certsStillToGenerate > 1
                            ? new BasicConstraints(certsStillToGenerate - 1)
                            : new BasicConstraints(false));
            PrivateKey signingKey = privateKeyOfEndCertififcate;
            ContentSigner build = tryWithAllProviders(
                    pi -> new JcaContentSignerBuilder(AlgorithmHelper.getSigningAlgNameFromKey(signingKey))
                            .setProvider(pi)
                            .build(signingKey));
            lastCert = tryWithAllProviders(po -> {
                return new JcaX509CertificateConverter().setProvider(po).getCertificate(nextV3CertBldr.build(build));
            });
            trustChain.addFirst(lastCert);
            privateKeyOfEndCertififcate = nextKeyPair.getPrivate();
            certsStillToGenerate--;
            if (certsStillToGenerate <= 0) {
                return;
            }
            if (withoutEndCert && certsStillToGenerate <= 1) {
                return;
            }
            lastIssuer = nextIssuer;
        }
    }

    /**
     * load keystore from file
     *
     * @param keyStoreFileName name of the key store file
     * @param password         keystore password
     * @throws Exception in case of error
     */
    public TrustChainAndPrivateKey(final String keyStoreFileName, final char[] password) throws Exception {
        this(TestCertUtility.loadKeystoreFromFile(keyStoreFileName, password), password);
    }

    /**
     * initilize from keystore
     *
     * @param keyStore the keystore to load from
     * @param password keystore password
     * @throws Exception in case of error
     */
    TrustChainAndPrivateKey(final KeyStore keyStore, final char[] password) throws Exception {
        for (final String aktAlias : Collections.list(keyStore.aliases())) {
            if (keyStore.isCertificateEntry(aktAlias)) {
                Certificate aktTrusted = keyStore.getCertificate(aktAlias);
                if (aktTrusted instanceof X509Certificate) {
                    trustAnchors.add((X509Certificate) aktTrusted);
                }
            }
        }
        for (final String aktAlias : Collections.list(keyStore.aliases())) {
            final Key privKey = keyStore.getKey(aktAlias, password);
            if (!(privKey instanceof PrivateKey)) {
                continue;
            }
            final Certificate certificate = keyStore.getCertificate(aktAlias);
            if (!(certificate instanceof X509Certificate)) {
                continue;
            }
            final Certificate[] foundChain = keyStore.getCertificateChain(aktAlias);
            for (final Certificate aktCert : foundChain) {
                trustChain.add((X509Certificate) aktCert);
            }
            privateKeyOfEndCertififcate = (PrivateKey) privKey;
            return;
        }
        throw new SecurityException("no chain in Keystore");
    }

    @Override
    public List<X509Certificate> getCertificateChain() {
        return new ArrayList<>(trustChain);
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKeyOfEndCertififcate;
    }

    public ProtectionProvider setEndEntityToProtect(final CMPCertificate certificate, final PrivateKey privateKey)
            throws Exception {
        final AlgorithmIdentifier protectionAlg = AlgorithmHelper.getSigningAlgIdFromKey(privateKey);

        final GeneralName senderName = new GeneralName(
                X500Name.getInstance(certificate.getX509v3PKCert().getSubject().getEncoded(ASN1Encoding.DER)));
        final DEROctetString senderKid = TestCertUtility.extractSubjectKeyIdentifierFromCert(
                TestCertUtility.certificateFromCmpCertificate(certificate));
        return new ProtectionProvider() {

            @Override
            public List<CMPCertificate> getProtectingExtraCerts() throws GeneralSecurityException {
                final List<CMPCertificate> ret = new ArrayList<>(trustChain.size());
                ret.add(certificate);
                for (final X509Certificate aktCert : trustChain) {
                    if (TestCertUtility.isSelfSigned(aktCert)) {
                        // chain root reached
                        break;
                    }
                    ret.add(TestCertUtility.cmpCertificateFromCertificate(aktCert));
                }
                return ret;
            }

            @Override
            public AlgorithmIdentifier getProtectionAlg() {
                return protectionAlg;
            }

            @Override
            public DERBitString getProtectionFor(final ProtectedPart protectedPart) throws GeneralSecurityException, IOException {
                final Signature sig =
                        AlgorithmHelper.getSignature(AlgorithmHelper.getSigningAlgNameFromKey(privateKey));
                sig.initSign(privateKey);
                sig.update(protectedPart.getEncoded(ASN1Encoding.DER));
                return new DERBitString(sig.sign());
            }

            @Override
            public GeneralName getSender() {
                return senderName;
            }

            @Override
            public DEROctetString getSenderKID() {
                return senderKid;
            }
        };
    }

    @Override
    public Collection<X509Certificate> getTrustedCertificates() {
        return trustAnchors;
    }

    @Override
    public Collection<X509Certificate> getAdditionalCerts() {
        return trustChain;
    }
}
