/*
 *  Copyright (c) 2026 Siemens AG
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
package com.siemens.pki.cmpracomponent.testutil.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateAuthority {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // ---------- Parameters object for extension tuning ----------
    public static final class IssueParams {
        public boolean isCA = false; // true for CA/ICA/ROOT
        public Integer pathLenConstraint = null; // e.g. 0 for ICA that issues only leaves
        public KeyUsage keyUsage = null; // if null, defaults based on isCA
        public KeyPurposeId[] extendedKeyUsages; // EKUs for EE/RA; omit for CA/ICA/ROOT
        public GeneralName[] subjectAltNames; // SANs (DNS/IP/URI/email …)
    }

    // ---------- Self-signed ROOT with extensions ----------
    public static X509Certificate selfSignedRoot(KeyPair keys, String dn, int pathLen) throws Exception {
        X500Name name = new X500Name(dn);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 1000),
                // 10 years – adjust as you like
                new Date(System.currentTimeMillis() + 3650L * 24 * 3600 * 1000),
                name,
                keys.getPublic());

        // --- Extensions ---
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // Basic Constraints: CA=true with pathLen
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));

        // KeyUsage: keyCertSign + cRLSign for roots
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        // Subject Key Identifier & Authority Key Identifier
        builder.addExtension(
                Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keys.getPublic()));
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(keys.getPublic())); // self for root

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    // ---------- Issued certificate (ICA / CA / RA / EE) with extensions ----------
    public static X509Certificate issueCertificate(
            KeyPair subjectKeys, X509Certificate issuerCert, PrivateKey issuerKey, String subjectDn, IssueParams params)
            throws Exception {

        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDn);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 1000),
                new Date(System.currentTimeMillis() + 1825L * 24 * 3600 * 1000), // 5 years default
                subject,
                subjectKeys.getPublic());

        // --- Extensions ---
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // SKI / AKI
        builder.addExtension(
                Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectKeys.getPublic()));
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(issuerCert.getPublicKey()));

        // BasicConstraints (present for all CAs; absent for EE/RA unless you want CA=true)
        if (params.isCA) {
            BasicConstraints bc = (params.pathLenConstraint == null)
                    ? new BasicConstraints(true)
                    : new BasicConstraints(params.pathLenConstraint);
            builder.addExtension(Extension.basicConstraints, true, bc);
        } else {
            // Explicitly mark as end-entity
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        }

        // KeyUsage
        KeyUsage ku = params.keyUsage != null
                ? params.keyUsage
                : (params.isCA
                        ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                        : new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement));
        builder.addExtension(Extension.keyUsage, true, ku);

        // EKU (usually only for end-entities / RAs)
        if (params.extendedKeyUsages != null && params.extendedKeyUsages.length > 0) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(params.extendedKeyUsages));
        }

        // SAN
        if (params.subjectAltNames != null && params.subjectAltNames.length > 0) {
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(params.subjectAltNames));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    // ---------- Helpers to build SAN arrays ----------
    public static GeneralName dns(String name) {
        return new GeneralName(GeneralName.dNSName, name);
    }

    public static GeneralName ip(String ip) {
        return new GeneralName(GeneralName.iPAddress, ip);
    }

    public static GeneralName uri(String u) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, u);
    }

    public static GeneralName email(String e) {
        return new GeneralName(GeneralName.rfc822Name, e);
    }

    public static GeneralName[] toGeneralNames(List<GeneralName> names) {
        return names == null ? new GeneralName[0] : names.toArray(GeneralName[]::new);
    }
}
