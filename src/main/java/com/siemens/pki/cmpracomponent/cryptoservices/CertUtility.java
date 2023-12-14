/*
 *  Copyright (c) 2022 Siemens AG
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
package com.siemens.pki.cmpracomponent.cryptoservices;

import static com.siemens.pki.cmpracomponent.cryptoservices.ProviderWrapper.tryWithAllProviders;
import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

/**
 * A utility class for certificate handling
 */
public class CertUtility {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * conversion function from X509 certificate to CMPCertificate
     *
     * @param cert certificate to convert
     * @return converted certificate
     * @throws CertificateException if certificate could not be converted from CMP
     *                              Certificate
     */
    public static CMPCertificate asCmpCertificate(final Certificate cert) throws CertificateException {
        return CMPCertificate.getInstance(cert.getEncoded());
    }

    /**
     * conversion function from X509 certificates to CMPCertificates
     *
     * @param certs certificates to convert
     * @return converted certificate
     * @throws CertificateException if certificate could not be converted from CMP
     *                              Certificate
     */
    public static CMPCertificate[] asCmpCertificates(final List<X509Certificate> certs) throws CertificateException {
        final CMPCertificate[] ret = new CMPCertificate[certs.size()];
        int index = 0;
        for (final X509Certificate aktCert : certs) {
            ret[index++] = asCmpCertificate(aktCert);
        }
        return ret;
    }

    /**
     * conversion function from byte to X509 certificate
     *
     * @param encoded byte string to encode
     * @return converted certificate
     * @throws CertificateException if certificate could not be converted from
     *                              encoded
     */
    public static X509Certificate asX509Certificate(final byte[] encoded) throws CertificateException {
        return (X509Certificate) tryWithAllProviders(p -> {
            ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);
            return CertificateFactory.getInstance("X.509", p).generateCertificate(inStream);
        });
    }

    /**
     * conversion function from CMPCertificate to X509 certificate
     *
     * @param cert certificate to convert
     * @return converted certificate
     * @throws CertificateException if certificate could not be converted from CMP
     *                              Certificate
     */
    public static X509Certificate asX509Certificate(final CMPCertificate cert) throws CertificateException {
        try {
            return asX509Certificate(cert.getEncoded(ASN1Encoding.DER));
        } catch (final IOException excpt) {
            throw new CertificateException(excpt);
        }
    }

    /**
     * conversion function from CMPCertificates to X509 certificates
     *
     * @param certs certificates to convert
     * @return converted certificate
     * @throws CertificateException if certificate could not be converted from CMP
     *                              Certificate
     */
    public static List<X509Certificate> asX509Certificates(final CMPCertificate[] certs) throws CertificateException {
        try {
            final ArrayList<X509Certificate> ret = new ArrayList<>(certs.length);
            for (final CMPCertificate aktCert : certs) {
                ret.add(asX509Certificate(aktCert.getEncoded(ASN1Encoding.DER)));
            }
            return ret;
        } catch (final IOException excpt) {
            throw new CertificateException(excpt);
        }
    }

    /**
     * fetch the SubjectKeyIdentifier from a cert
     *
     * @param cert cert to fetch the SubjectKeyIdentifier
     * @return the SubjectKeyIdentifier encoded as DEROctetString
     */
    public static DEROctetString extractSubjectKeyIdentifierFromCert(final X509Certificate cert) {
        final byte[] extensionValueAsDerEncodedOctetString =
                cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId());
        return ifNotNull(
                extensionValueAsDerEncodedOctetString,
                x -> new DEROctetString(ASN1OctetString.getInstance(
                                ASN1OctetString.getInstance(x).getOctets())
                        .getOctets()));
    }

    /**
     * generate a new randomly filled byte array
     *
     * @param length size of byte array to return
     * @return a new randomly filled byte array
     */
    public static byte[] generateRandomBytes(final int length) {
        final byte[] ret = new byte[length];
        RANDOM.nextBytes(ret);
        return ret;
    }

    /**
     * create an {@link X509CRL} from a byte string
     *
     * @param encodedCrl DER encoded CRL
     * @return parsed CRL
     * @throws GeneralSecurityException in case of parsing error
     */
    public static X509CRL parseCrl(byte[] encodedCrl) throws GeneralSecurityException {
        return (X509CRL) tryWithAllProviders(p -> {
            ByteArrayInputStream inStream = new ByteArrayInputStream(encodedCrl);
            return CertificateFactory.getInstance("X.509", p).generateCRL(inStream);
        });
    }

    /**
     * Checks whether given X.509 certificate is intermediate certificate and not
     * self-signed.
     *
     * @param cert certificate to be checked
     * @return <code>true</code> if the certificate is intermediate and not
     *         self-signed
     */
    public static boolean isIntermediateCertificate(final X509Certificate cert) {
        try {
            // Try to verify certificate signature with its own public key
            final PublicKey key = cert.getPublicKey();
            cert.verify(key);
            // self-signed
            return false;
        } catch (final SignatureException | InvalidKeyException keyEx) {
            // Invalid key --> definitely not self-signed
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            // processing error, could be self-signed
            return false;
        }
    }

    // utility class
    private CertUtility() {}

    /**
     * extract PublicKey from SubjectPublicKeyInfo
     * @param subjectPublicKeyInfo the subjectPublicKeyInfo
     * @return extracted PublicKey
     * @throws NoSuchAlgorithmException if PublicKey algorithm is not known
     * @throws IOException if subjectPublicKeyInfo could not parsed
     */
    public static PublicKey parsePublicKey(final SubjectPublicKeyInfo subjectPublicKeyInfo)
            throws NoSuchAlgorithmException, IOException {
        try {
            return tryWithAllProviders(p -> KeyFactory.getInstance(
                            subjectPublicKeyInfo.getAlgorithm().getAlgorithm().toString(), p)
                    .generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER))));
        } catch (NoSuchAlgorithmException | IOException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * check integrity of an PKCS#10 request
     * @param p10Request request to check
     * @return <code>true</code> if request is valid
     * @throws PKCSException if request could not be parsed
     * @throws OperatorCreationException if the signature cannot be processed or is inappropriate
     */
    public static boolean validateP10Request(final PKCS10CertificationRequest p10Request)
            throws PKCSException, OperatorCreationException {
        try {
            return tryWithAllProviders(p -> p10Request.isSignatureValid(new JcaX509ContentVerifierProviderBuilder()
                    .setProvider(p)
                    .build(p10Request.getSubjectPublicKeyInfo())));
        } catch (PKCSException | OperatorCreationException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
