/*
 *  Copyright (c) 2023 Siemens AG
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
package com.siemens.pki.cmpracomponent.test;

import com.siemens.pki.cmpracomponent.cryptoservices.KeyPairGeneratorFactory;
import com.siemens.pki.cmpracomponent.test.framework.TestCertificateFactory;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;

/**
 * initial creation of test credentials
 *
 */
public class TestCreateTestCertificateChains {

    private static final char[] STORE_PASSWORD = "Password".toCharArray();
    private static final File CREDENTIAL_ROOT =
            new File("src/test/java/com/siemens/pki/cmpracomponent/test/config/credentials");

    private void createEnrollTestCertificateChain(
            final String subjectPrefix, KeyPairGenerator keyPairGenerator, String signatureAlgorithm)
            throws GeneralSecurityException, CertificateException, OperatorCreationException, NoSuchAlgorithmException,
                    IOException, KeyStoreException, FileNotFoundException {
        final KeyPair rootKeypair = keyPairGenerator.generateKeyPair();
        final X509Certificate rootCert =
                TestCertificateFactory.createRootCertificate(subjectPrefix, rootKeypair, signatureAlgorithm);

        final KeyPair issuerKeypair = keyPairGenerator.generateKeyPair();
        final X509Certificate issuerCert = TestCertificateFactory.createIssuerCertificate(
                subjectPrefix, rootCert, rootKeypair.getPrivate(), issuerKeypair.getPublic(), signatureAlgorithm);

        try (JcaPEMWriter pw =
                new JcaPEMWriter(new FileWriter(new File(CREDENTIAL_ROOT, subjectPrefix + "_Chain.pem")))) {
            pw.writeObject(rootCert);
            pw.writeObject(issuerCert);
        }
        try (JcaPEMWriter pw =
                new JcaPEMWriter(new FileWriter(new File(CREDENTIAL_ROOT, subjectPrefix + "_Root.pem")))) {
            pw.writeObject(rootCert);
        }
        final KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, STORE_PASSWORD);
        keystore.setKeyEntry(
                "cert", issuerKeypair.getPrivate(), STORE_PASSWORD, new Certificate[] {issuerCert, rootCert});
        try (final OutputStream ksout =
                new FileOutputStream(new File(CREDENTIAL_ROOT, subjectPrefix + "_Keystore.p12"))) {
            keystore.store(ksout, STORE_PASSWORD);
        }
    }

    private void createFullTestCertificateChain(
            final String subjectPrefix,
            KeyPairGenerator keyPairGenerator,
            String signatureAlgorithm,
            Extension... eeExtensions)
            throws GeneralSecurityException, CertificateException, OperatorCreationException, NoSuchAlgorithmException,
                    IOException, KeyStoreException, FileNotFoundException {
        final KeyPair rootKeypair = keyPairGenerator.generateKeyPair();
        final X509Certificate rootCert =
                TestCertificateFactory.createRootCertificate(subjectPrefix, rootKeypair, signatureAlgorithm);

        final KeyPair issuerKeypair = keyPairGenerator.generateKeyPair();
        final X509Certificate issuerCert = TestCertificateFactory.createIssuerCertificate(
                subjectPrefix, rootCert, rootKeypair.getPrivate(), issuerKeypair.getPublic(), signatureAlgorithm);

        final KeyPair eeKeypair = keyPairGenerator.generateKeyPair();
        final X509Certificate eeCert = TestCertificateFactory.createEndEntityCertificate(
                subjectPrefix,
                issuerCert,
                issuerKeypair.getPrivate(),
                eeKeypair.getPublic(),
                signatureAlgorithm,
                eeExtensions);
        try (JcaPEMWriter pw =
                new JcaPEMWriter(new FileWriter(new File(CREDENTIAL_ROOT, subjectPrefix + "_Chain.pem")))) {
            pw.writeObject(rootCert);
            pw.writeObject(issuerCert);
            pw.writeObject(eeCert);
        }
        try (JcaPEMWriter pw =
                new JcaPEMWriter(new FileWriter(new File(CREDENTIAL_ROOT, subjectPrefix + "_Root.pem")))) {
            pw.writeObject(rootCert);
        }
        final KeyStore keystore = KeyStore.getInstance("PKCS12", "SUN");
        keystore.load(null, STORE_PASSWORD);
        keystore.setKeyEntry(
                "cert", eeKeypair.getPrivate(), STORE_PASSWORD, new Certificate[] {eeCert, issuerCert, rootCert});
        try (final OutputStream ksout =
                new FileOutputStream(new File(CREDENTIAL_ROOT, subjectPrefix + "_Keystore.p12"))) {
            keystore.store(ksout, STORE_PASSWORD);
        }
    }

    @Test
    // @Ignore("execute if test credentials need a refresh")
    public void createTestCertificateChains() throws OperatorCreationException, IOException, GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = KeyPairGeneratorFactory.getEcKeyPairGenerator("secp521r1");
        createEnrollTestCertificateChain("ENROLL", keyPairGenerator, "SHA512WITHECDSA");
        createFullTestCertificateChain("CMP_CA", keyPairGenerator, "SHA512WITHECDSA");
        createFullTestCertificateChain(
                "CMP_LRA_UPSTREAM",
                keyPairGenerator,
                "SHA512WITHECDSA",
                TestCertificateFactory.createExtendedKeyUsageExtension(
                        KeyPurposeId.id_kp_cmcRA, KeyPurposeId.anyExtendedKeyUsage));
        createFullTestCertificateChain(
                "CMP_LRA_DOWNSTREAM",
                keyPairGenerator,
                "SHA512WITHECDSA",
                TestCertificateFactory.createExtendedKeyUsageExtension(
                        KeyPurposeId.id_kp_cmKGA, KeyPurposeId.anyExtendedKeyUsage));
        createFullTestCertificateChain("CMP_EE", keyPairGenerator, "SHA512WITHECDSA");
        //		createTestCertificateChain("TLS", keyPairGenerator, "SHA512WITHECDSA", TestCertificateFactory
        //				.createExtendedKeyUsageExtension(KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth),
        //				TestCertificateFactory.createSubjectAlternativeNameExtension("localhost"));
    }
}
