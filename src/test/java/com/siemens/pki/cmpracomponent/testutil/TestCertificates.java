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
package com.siemens.pki.cmpracomponent.testutil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Utility class for generating small, self‑signed dummy X.509 certificates wrapped as
 * {@link CMPCertificate} instances. This class is intended solely for use in unit tests within the
 * CMP RA component.
 *
 * <h2>Purpose</h2>
 * <p>
 * Many unit tests require realistic but lightweight X.509 certificates to populate CMP structures
 * such as {@code extraCerts}. Constructing full certificate chains or using production‑grade PKI
 * material is unnecessary overhead. This utility:
 * </p>
 *
 * <ul>
 * <li>Generates minimal self‑signed certificates suitable for equality checks, set membership, and
 * ASN.1 structure validation.</li>
 * <li>Provides an inbuilt RSA key pair used for multiple certificates until explicitly
 * rotated.</li>
 * <li>Allows callers to request a certificate using the default key pair or a caller‑provided key
 * pair.</li>
 * <li>Ensures deterministic and thread‑safe behavior across all tests.</li>
 * </ul>
 *
 * <h2>Design Characteristics</h2>
 * <ul>
 * <li><strong>Test‑Only:</strong> All keys and certificates are dummy objects, not intended for any
 * real PKI or security use.</li>
 * <li><strong>Thread‑Safe:</strong> Methods synchronize on an internal lock to guarantee safe
 * concurrent access during parallel test execution.</li>
 * <li><strong>Convenient Error Handling:</strong> All failures are wrapped in unchecked
 * {@link IllegalStateException} to avoid boilerplate in tests.</li>
 * <li><strong>Key Rotation:</strong> The inbuilt key pair can be refreshed to produce certificates
 * with a different public key.</li>
 * </ul>
 *
 * <h2>Typical Usage</h2>
 *
 * <pre>{@code
 * CMPCertificate a = TestCertificates.newCert("A");
 * CMPCertificate b = TestCertificates.newCert("B");
 *
 * // Rotate to a new dummy key pair
 * TestCertificates.rotateKeyPair();
 *
 * CMPCertificate c = TestCertificates.newCert("C"); // uses new key
 * }</pre>
 *
 * <h2>Not Intended For</h2>
 * <ul>
 * <li>Security testing</li>
 * <li>Production environments</li>
 * <li>Cryptographic assurance or trust evaluation</li>
 * <li>Interoperability testing requiring standards‑compliant certificate chains</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>
 * All public methods are thread‑safe. The class synchronizes on a private lock to guard key pair
 * rotation and certificate generation using shared state.
 * </p>
 */
public final class TestCertificates {

    /** RSA key size used for all generated dummy certificates. */
    private static final int KEY_SIZE = 2048;

    /** Signature algorithm used for self‑signing test certificates. */
    private static final String SIGNATURE_ALG = "SHA256withRSA";

    /** Lock object to ensure thread‑safe key rotation and certificate creation. */
    private static final Object LOCK = new Object();

    /**
     * Counter used to assign a unique serial number to each generated certificate. Ensures
     * predictable, collision‑free serials for test purposes.
     */
    private static final AtomicLong SERIAL_COUNTER = new AtomicLong(1);

    /** The inbuilt key pair used by {@link #newCert(String)} until rotated. */
    private static KeyPair currentKeyPair;

    static {
        currentKeyPair = safeGenKeyPair();
    }

    private TestCertificates() {
        // Prevent instantiation; utility class only.
    }

    /**
     * Returns the currently active inbuilt RSA key pair used by {@link #newCert(String)}.
     *
     * @return the current key pair
     */
    public static KeyPair currentKeyPair() {
        synchronized (LOCK) {
            return currentKeyPair;
        }
    }

    /**
     * Rotates the inbuilt RSA key pair. All subsequent calls to {@link #newCert(String)} will use the
     * newly generated key.
     *
     * @return the new current key pair
     * @throws IllegalStateException if RSA key generation fails
     */
    public static KeyPair rotateKeyPair() {
        synchronized (LOCK) {
            currentKeyPair = safeGenKeyPair();
            return currentKeyPair;
        }
    }

    /**
     * Creates a self‑signed certificate using the current inbuilt key pair. The subject DN will be
     * {@code CN=<cn>}.
     *
     * @param cn the common name for the certificate subject
     * @return a dummy {@link CMPCertificate} suitable for unit tests
     * @throws IllegalStateException if certificate creation fails
     */
    public static CMPCertificate newCert(String cn) {
        synchronized (LOCK) {
            return newCert(cn, currentKeyPair);
        }
    }

    /**
     * Creates a self‑signed certificate using the caller‑provided key pair.
     *
     * <p>
     * The certificate is constructed with:
     * </p>
     * <ul>
     * <li>Subject and issuer: {@code CN=<cn>}</li>
     * <li>A unique serial number</li>
     * <li>A very short validity period (sufficient for tests)</li>
     * <li>Signature algorithm: {@code SHA256withRSA}</li>
     * </ul>
     *
     * @param cn the subject common name
     * @param keyPair the key pair used for the certificate’s subject public key and signing key
     * @return a dummy {@link CMPCertificate}
     * @throws IllegalStateException if certificate creation fails
     */
    public static CMPCertificate newCert(String cn, KeyPair keyPair) {
        try {
            X500Name subject = new X500Name("CN=" + cn);

            Date notBefore = new Date(System.currentTimeMillis() - 1000);
            Date notAfter = new Date(System.currentTimeMillis() + 3600000);

            BigInteger serial = BigInteger.valueOf(SERIAL_COUNTER.getAndIncrement());

            SubjectPublicKeyInfo spki =
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

            X509v3CertificateBuilder builder =
                    new X509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, spki);

            ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALG).build(keyPair.getPrivate());

            Certificate cert = builder.build(signer).toASN1Structure();

            return new CMPCertificate(cert);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate test certificate for CN=" + cn, e);
        }
    }

    /**
     * Generates a new RSA key pair using the configured key size. Intended for internal use only.
     *
     * @return a newly generated RSA key pair
     * @throws IllegalStateException if the JCA provider fails or unsupported algorithms are used
     */
    private static KeyPair safeGenKeyPair() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(KEY_SIZE);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate test RSA key pair", e);
        }
    }
}
