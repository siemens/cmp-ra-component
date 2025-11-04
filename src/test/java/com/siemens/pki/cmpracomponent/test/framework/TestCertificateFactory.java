/*
 *  Copyright (c) 2025 Siemens AG
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

import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** a factory for X.509 certificates */
public class TestCertificateFactory {

    interface CertParams {

        default Collection<Extension> getExtensions()
                throws NoSuchAlgorithmException, IOException, CertificateEncodingException {
            return null;
        }

        String getIssuer();

        default X500Principal getIssuerX500Principal() {
            return new X500Principal(getIssuer());
        }

        PublicKey getPublicKey();

        default BigInteger getSerial() {
            return BigInteger.valueOf(++SERIAL);
        }

        default String getSignatureAlgorithm() {
            return AlgorithmHelper.getSigningAlgNameFromKey(getSigningPrivateKey());
        }

        PrivateKey getSigningPrivateKey();

        String getSubject();

        default X500Principal getSubjectX500Principal() {
            return new X500Principal(getSubject());
        }

        default long getValidityDays() {
            return 10 * 365L;
        }
    }

    private static long SERIAL = 0xaaaa00000000L;

    private static final Logger LOGGER = LoggerFactory.getLogger(TestCertificateFactory.class);

    static JcaX509ExtensionUtils EXTUTILS;

    static {
        try {
            EXTUTILS = new JcaX509ExtensionUtils();
        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error("init JcaX509ExtensionUtils", e);
            EXTUTILS = null;
        }
    }

    private static X509Certificate buildCertifcate(CertParams params)
            throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, IOException {
        final long now = System.currentTimeMillis();
        final X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                params.getIssuerX500Principal(),
                params.getSerial(),
                new Date(now - 60 * 60 * 1000L),
                new Date(now + params.getValidityDays() * 24 * 60 * 60 * 1000L),
                params.getSubjectX500Principal(),
                params.getPublicKey());
        final Collection<Extension> extensions = params.getExtensions();
        if (extensions != null) {
            for (final Extension ext : extensions) {
                if (ext != null) {
                    v3CertBldr.addExtension(ext);
                }
            }
        }
        ContentSigner signer = new JcaContentSignerBuilder(params.getSignatureAlgorithm())
                .setProvider(CertUtility.getBouncyCastleProvider())
                .build(params.getSigningPrivateKey());
        return new JcaX509CertificateConverter()
                .setProvider(CertUtility.getBouncyCastleProvider())
                .getCertificate(v3CertBldr.build(signer));
    }

    private static Extension createAiaOcspExtension(final String url) throws IOException {
        return new Extension(
                Extension.authorityInfoAccess,
                false,
                new AuthorityInformationAccess(new AccessDescription(
                                AccessDescription.id_ad_ocsp,
                                new GeneralName(GeneralName.uniformResourceIdentifier, url)))
                        .getEncoded());
    }

    @SuppressWarnings("unused")
    private static Extension createAiaOcspExtension(final URL url) throws IOException {
        return createAiaOcspExtension(url.toExternalForm());
    }

    private static Extension createAuthorityKeyExtension(final PublicKey publicKey)
            throws NoSuchAlgorithmException, IOException {
        return new Extension(
                Extension.authorityKeyIdentifier,
                false,
                EXTUTILS.createAuthorityKeyIdentifier(publicKey).getEncoded());
    }

    private static Extension createAuthorityKeyExtension(final X509Certificate signingCertificate)
            throws NoSuchAlgorithmException, IOException, CertificateEncodingException {
        return new Extension(
                Extension.authorityKeyIdentifier,
                false,
                EXTUTILS.createAuthorityKeyIdentifier(signingCertificate).getEncoded());
    }

    private static Extension createBasicConstraintsExtension(final int pathlen) throws IOException {
        final BasicConstraints basicConstraints =
                pathlen >= 0 ? new BasicConstraints(pathlen) : new BasicConstraints(false);
        return new Extension(Extension.basicConstraints, true, basicConstraints.getEncoded());
    }

    @SuppressWarnings("unused")
    private static Extension createCertificatePolicy(String policy) throws IOException {
        return new Extension(
                Extension.certificatePolicies,
                false,
                new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policy))).getEncoded());
    }

    private static Extension createCrlDistributionPointsExtension(final String url) throws Exception {
        return new Extension(
                Extension.cRLDistributionPoints,
                false,
                new CRLDistPoint(new DistributionPoint[] {
                            new DistributionPoint(
                                    new DistributionPointName(new GeneralNames(
                                            new GeneralName(GeneralName.uniformResourceIdentifier, url))),
                                    null,
                                    null)
                        })
                        .getEncoded());
    }

    @SuppressWarnings("unused")
    private static Extension createCrlDistributionPointsExtension(final URL url) throws Exception {
        return createCrlDistributionPointsExtension(url.toExternalForm());
    }

    public static X509Certificate createEndEntityCertificate(
            String subjectPrefix,
            X509Certificate signerCert,
            PrivateKey signingKey,
            PublicKey publickey,
            String signatureAlgorithm,
            Extension... eeExtensions)
            throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, IOException {
        final String subject = String.format("CN=%s_ENDENTITY, OU=TestDepartment, O=Siemens, C=DE", subjectPrefix);

        final CertParams params = new CertParams() {

            @Override
            public Collection<Extension> getExtensions()
                    throws NoSuchAlgorithmException, IOException, CertificateEncodingException {
                Extension keyUsageExtension;
                if (publickey.getAlgorithm().toUpperCase().startsWith("RSA")) {
                    keyUsageExtension = createKeyUsageExtension(KeyUsage.digitalSignature);
                } else {
                    keyUsageExtension = createKeyUsageExtension(KeyUsage.digitalSignature, KeyUsage.keyAgreement);
                }
                final ArrayList<Extension> ret = new ArrayList<>();
                ret.addAll(Arrays.asList(
                        createAuthorityKeyExtension(signerCert),
                        createSubjectKeyExtension(getPublicKey()),
                        createBasicConstraintsExtension(-1),
                        keyUsageExtension));
                if (eeExtensions != null) {
                    ret.addAll(Arrays.asList(eeExtensions));
                }
                return ret;
            }

            @Override
            public String getIssuer() {
                return null;
            }

            @Override
            public X500Principal getIssuerX500Principal() {
                return signerCert.getSubjectX500Principal();
            }

            @Override
            public PublicKey getPublicKey() {
                return publickey;
            }

            @Override
            public String getSignatureAlgorithm() {
                return signatureAlgorithm;
            }

            @Override
            public PrivateKey getSigningPrivateKey() {
                return signingKey;
            }

            @Override
            public String getSubject() {
                return subject;
            }

            @Override
            public long getValidityDays() {
                return 1827;
            }
        };
        return buildCertifcate(params);
    }

    // KeyPurposeId.id_kp_serverAuth | KeyPurposeId.id_kp_clientAuth
    public static Extension createExtendedKeyUsageExtension(final KeyPurposeId... extendedKeyUsages)
            throws IOException {
        return new Extension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(extendedKeyUsages).getEncoded());
    }

    public static X509Certificate createIssuerCertificate(
            String subjectPrefix,
            X509Certificate signerCert,
            PrivateKey signingKey,
            PublicKey publickey,
            String signatureAlgorithm)
            throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, IOException {
        final String subject = String.format("CN=%s_ISSUER, OU=TestDepartment, O=Siemens, C=DE", subjectPrefix);

        final CertParams params = new CertParams() {

            @Override
            public Collection<Extension> getExtensions()
                    throws NoSuchAlgorithmException, IOException, CertificateEncodingException {

                return Arrays.asList(
                        createAuthorityKeyExtension(signerCert),
                        createSubjectKeyExtension(getPublicKey()),
                        createKeyUsageExtension(KeyUsage.keyCertSign, KeyUsage.cRLSign, KeyUsage.digitalSignature),
                        createBasicConstraintsExtension(0));
            }

            @Override
            public String getIssuer() {
                return null;
            }

            @Override
            public X500Principal getIssuerX500Principal() {
                return signerCert.getSubjectX500Principal();
            }

            @Override
            public PublicKey getPublicKey() {
                return publickey;
            }

            @Override
            public String getSignatureAlgorithm() {
                return signatureAlgorithm;
            }

            @Override
            public PrivateKey getSigningPrivateKey() {
                return signingKey;
            }

            @Override
            public String getSubject() {
                return subject;
            }

            @Override
            public long getValidityDays() {
                return 1827;
            }
        };
        return buildCertifcate(params);
    }

    // KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign
    private static Extension createKeyUsageExtension(final int... keyUsages) throws IOException {
        int keyUsage = 0;
        for (final int aktUsage : keyUsages) {
            keyUsage |= aktUsage;
        }
        return new Extension(Extension.keyUsage, true, new KeyUsage(keyUsage).getEncoded());
    }

    public static X509Certificate createRootCertificate(
            String subjectPrefix, KeyPair keyPair, String signatureAlgorithm)
            throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, IOException {
        final String issuer = String.format("CN=%s_ROOT, OU=TestDepartment, O=Siemens, C=DE", subjectPrefix);

        final CertParams params = new CertParams() {

            @Override
            public Collection<Extension> getExtensions() throws NoSuchAlgorithmException, IOException {
                return Arrays.asList(
                        createAuthorityKeyExtension(getPublicKey()),
                        createSubjectKeyExtension(getPublicKey()),
                        createBasicConstraintsExtension(1),
                        createKeyUsageExtension(KeyUsage.keyCertSign, KeyUsage.cRLSign, KeyUsage.digitalSignature));
            }

            @Override
            public String getIssuer() {
                return issuer;
            }

            @Override
            public PublicKey getPublicKey() {
                return keyPair.getPublic();
            }

            @Override
            public String getSignatureAlgorithm() {
                return signatureAlgorithm;
            }

            @Override
            public PrivateKey getSigningPrivateKey() {
                return keyPair.getPrivate();
            }

            @Override
            public String getSubject() {
                return issuer;
            }

            @Override
            public long getValidityDays() {
                return 4383;
            }
        };
        return buildCertifcate(params);
    }

    // GeneralName.iPAddress, GeneralName.dNSName, GeneralName.rfc822Name
    private static Extension createSubjectAlternativeNameExtension(final GeneralName... generalNames)
            throws IOException {
        final GeneralNamesBuilder gnb = new GeneralNamesBuilder();
        for (final GeneralName gn : generalNames) {
            gnb.addName(gn);
        }
        return new Extension(Extension.subjectAlternativeName, true, gnb.build().getEncoded());
    }

    public static Extension createSubjectAlternativeNameExtension(final String... hostnames) throws IOException {
        final GeneralName[] generalNames = new GeneralName[hostnames.length];
        for (int i = 0; i < hostnames.length; i++) {
            generalNames[i] = new GeneralName(GeneralName.dNSName, hostnames[i]);
        }
        return createSubjectAlternativeNameExtension(generalNames);
    }

    private static Extension createSubjectKeyExtension(final PublicKey subjectPublicKey)
            throws NoSuchAlgorithmException, IOException {
        return new Extension(
                Extension.subjectKeyIdentifier,
                false,
                EXTUTILS.createSubjectKeyIdentifier(subjectPublicKey).getEncoded());
    }
}
