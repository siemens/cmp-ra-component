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
package com.siemens.pki.cmpracomponent.test.framework;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertReqTemplateContent;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.CrlUpdateRetrievalHandler;
import com.siemens.pki.cmpracomponent.configuration.GetCaCertificatesHandler;
import com.siemens.pki.cmpracomponent.configuration.GetCertificateRequestTemplateHandler;
import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler;
import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler.RootCaCertificateUpdateResponse;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.KeyPairGeneratorFactory;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.protection.ProtectionProviderFactory;
import com.siemens.pki.cmpracomponent.util.MessageDumper;

/**
 * builder class for {@link Configuration} objects
 *
 *
 */
public class ConfigurationFactory {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(ConfigurationFactory.class);

    private static KeyPairGenerator keyGenerator;

    public static ProtectionProvider eeSignaturebasedProtectionProvider;

    public static ProtectionProvider eePbmac1ProtectionProvider;

    private static ProtectionProvider eePasswordbasedProtectionProvider;

    public static Configuration buildPasswordbasedDownstreamConfiguration()
            throws KeyStoreException, Exception {
        final CredentialContext downstreamCredentials =
                new SharedSecret("PBMAC1", TestUtils.PASSWORD);
        final VerificationContext downstreamTrust =
                new PasswordValidationCredentials(TestUtils.PASSWORD);

        final CredentialContext upstreamCredentials =
                new TrustChainAndPrivateKey(
                        "credentials/CMP_LRA_UPSTREAM_Keystore.p12",
                        "Password".toCharArray());
        final VerificationContext upstreamTrust =
                new SignatureValidationCredentials(
                        "credentials/CMP_CA_Root.pem", null);
        final SignatureValidationCredentials enrollmentTrust =
                new SignatureValidationCredentials(
                        "credentials/ENROLL_Root.pem", null);

        final Configuration config = buildSimpleRaConfiguration(
                downstreamCredentials, downstreamTrust, upstreamCredentials,
                upstreamTrust, enrollmentTrust);
        return config;
    }

    public static Configuration buildSignatureBasedDownstreamConfiguration()
            throws KeyStoreException, Exception {
        final TrustChainAndPrivateKey downstreamCredentials =
                new TrustChainAndPrivateKey(
                        "credentials/CMP_LRA_DOWNSTREAM_Keystore.p12",
                        "Password".toCharArray());
        final SignatureValidationCredentials downstreamTrust =
                new SignatureValidationCredentials(
                        "credentials/CMP_EE_Root.pem", null);
        final TrustChainAndPrivateKey upstreamCredentials =
                new TrustChainAndPrivateKey(
                        "credentials/CMP_LRA_UPSTREAM_Keystore.p12",
                        "Password".toCharArray());
        final SignatureValidationCredentials upstreamTrust =
                new SignatureValidationCredentials(
                        "credentials/CMP_CA_Root.pem", null);
        final SignatureValidationCredentials enrollmentTrust =
                new SignatureValidationCredentials(
                        "credentials/ENROLL_Root.pem", null);

        return buildSimpleRaConfiguration(downstreamCredentials,
                downstreamTrust, upstreamCredentials, upstreamTrust,
                enrollmentTrust);
    }

    public static Configuration buildSignatureBasedDownstreamOnlyConfiguration()
            throws KeyStoreException, Exception {
        final TrustChainAndPrivateKey downstreamCredentials =
                new TrustChainAndPrivateKey(
                        "credentials/CMP_LRA_DOWNSTREAM_Keystore.p12",
                        "Password".toCharArray());
        final SignatureValidationCredentials downstreamTrust =
                new SignatureValidationCredentials(
                        "credentials/CMP_EE_Root.pem", null);

        return new Configuration() {
            @Override
            public CkgContext getCkgConfiguration(final String certProfile,
                    final int bodyType) {
                fail(String.format(
                        "getCkgConfiguration called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType)));
                return null;
            }

            @Override
            public CmpMessageInterface getDownstreamConfiguration(
                    final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getDownstreamConfiguration called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return new CmpMessageInterface() {

                    @Override
                    public VerificationContext getInputVerification() {
                        return downstreamTrust;
                    }

                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return null;
                    }

                    @Override
                    public CredentialContext getOutputCredentials() {
                        try {
                            return downstreamCredentials;
                        } catch (final Exception e) {
                            throw new RuntimeException(e);
                        }
                    }

                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.reprotect;
                    }

                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isCacheExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isMessageTimeDeviationAllowed(
                            final long deviation) {
                        return true;
                    }
                };
            }

            @Override
            public VerificationContext getEnrollmentTrust(
                    final String certProfile, final int bodyType) {
                fail(String.format(
                        "getEnrollmentTrust called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType)));
                return null;
            }

            @Override
            public boolean getForceRaVerifyOnUpstream(final String certProfile,
                    final int bodyType) {
                fail(String.format(
                        "getForceRaVerifyOnUpstream called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType)));
                return false;
            }

            @Override
            public InventoryInterface getInventory(final String certProfile,
                    final int bodyType) {
                LOGGER.debug(
                        "getInventory called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return new InventoryInterface() {

                    @Override
                    public CheckAndModifyResult checkAndModifyCertRequest(
                            final byte[] transactionID,
                            final String requesterDn, final byte[] certTemplate,
                            final String requestedSubjectDn) {
                        LOGGER.debug(
                                "checkAndModifyCertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID), requesterDn,
                                requestedSubjectDn);
                        return new CheckAndModifyResult() {

                            @Override
                            public byte[] getUpdatedCertTemplate() {
                                return null;
                            }

                            @Override
                            public boolean isGranted() {
                                return true;
                            }
                        };
                    }

                    @Override
                    public boolean checkP10CertRequest(
                            final byte[] transactionID,
                            final String requesterDn,
                            final byte[] pkcs10CertRequest,
                            final String requestedSubjectDn) {
                        LOGGER.debug(
                                "checkP10CertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID), requesterDn,
                                requestedSubjectDn);
                        return false;
                    }

                    @Override
                    public boolean learnEnrollmentResult(
                            final byte[] transactionID,
                            final byte[] certificate, final String serialNumber,
                            final String subjectDN, final String issuerDN) {
                        LOGGER.debug(
                                "learnEnrollmentResult called with transactionID: {}, serialNumber: {}, subjectDN: {}, issuerDN: {}",
                                new BigInteger(transactionID), serialNumber,
                                subjectDN, issuerDN);
                        return true;
                    }
                };
            }

            @Override
            public int getRetryAfterTimeInSeconds(final String certProfile,
                    final int bodyType) {
                fail(String.format(
                        "getRetryAfterTimeInSeconds called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType)));
                return 100;
            }

            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    final String certProfile, final String infoTypeOid) {
                LOGGER.debug(
                        "getSupportMessageHandler called with certprofile: {}, infoTypeOid: {}",
                        certProfile, infoTypeOid);
                if (CMPObjectIdentifiers.id_it_caCerts.getId()
                        .equals(infoTypeOid)) {
                    return (GetCaCertificatesHandler) () -> {
                        try {
                            return TestCertUtility.loadCertificatesFromFile(
                                    "credentials/CaCerts.pem");
                        } catch (final Exception e) {
                            throw new RuntimeException(e);
                        }
                    };
                }
                if (CMPObjectIdentifiers.id_it_rootCaCert.getId()
                        .equals(infoTypeOid)) {
                    LOGGER.debug("id_it_rootCaCert called with certprofile: {}",
                            certProfile);
                    return (GetRootCaCertificateUpdateHandler) oldRootCaCertificate -> {
                        assertNotNull(oldRootCaCertificate);
                        try {
                            LOGGER.debug(
                                    "oldRootCaCertificate :" + MessageDumper
                                            .dumpAsn1Object(TestCertUtility
                                                    .cmpCertificateFromCertificate(
                                                            oldRootCaCertificate)));
                        } catch (final CertificateException e1) {
                            throw new RuntimeException(e1);
                        }

                        return new RootCaCertificateUpdateResponse() {

                            @Override
                            public X509Certificate getNewWithNew() {
                                try {
                                    return TestCertUtility
                                            .loadCertificatesFromFile(
                                                    "credentials/newWithNew.pem")
                                            .get(0);
                                } catch (final Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }

                            @Override
                            public X509Certificate getNewWithOld() {
                                try {
                                    return TestCertUtility
                                            .loadCertificatesFromFile(
                                                    "credentials/newWithOld.pem")
                                            .get(0);
                                } catch (final Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }

                            @Override
                            public X509Certificate getOldWithNew() {
                                try {
                                    return TestCertUtility
                                            .loadCertificatesFromFile(
                                                    "credentials/oldWithNew.pem")
                                            .get(0);
                                } catch (final Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }

                        };
                    };
                }
                if (CMPObjectIdentifiers.id_it_certReqTemplate.getId()
                        .equals(infoTypeOid)) {
                    LOGGER.debug(
                            "id_it_certReqTemplate called with certprofile: {}",
                            certProfile);
                    return (GetCertificateRequestTemplateHandler) () -> {
                        try {
                            return generateCertReqTemplateContent()
                                    .getEncoded();
                        } catch (final IOException e) {
                            throw new RuntimeException(e);
                        }
                    };
                }
                if (CMPObjectIdentifiers.id_it_crlStatusList.getId()
                        .equals(infoTypeOid)) {
                    LOGGER.debug(
                            "id_it_crlStatusList called with certprofile: {}",
                            certProfile);
                    return (CrlUpdateRetrievalHandler) (dpn, issuer,
                            thisUpdate) -> {
                        try {
                            LOGGER.debug(
                                    "CrlUpdateRetrieval OID: {}, dpn:{}, issuer:{}, thisUpdate: {}",
                                    infoTypeOid, dpn, issuer, thisUpdate);
                            return Collections
                                    .singletonList((X509CRL) CertificateFactory
                                            .getInstance("X.509")
                                            .generateCRL(ConfigFileLoader
                                                    .getConfigFileAsStream(
                                                            "credentials/CRL.der")));
                        } catch (CRLException | CertificateException
                                | IOException e) {
                            throw new RuntimeException(e);
                        }
                    };
                }
                fail("unexpected OID " + infoTypeOid);
                return null;
            }

            @Override
            public CmpMessageInterface getUpstreamConfiguration(
                    final String certProfile, final int bodyType) {
                fail(String.format(
                        "getUpstreamConfiguration called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType)));
                return null;
            }

            @Override
            public boolean isRaVerifiedAcceptable(final String certProfile,
                    final int bodyType) {
                fail(String.format(
                        "isRaVerifiedAcceptable called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType)));
                return false;
            }

        };
    }

    public static Configuration buildSimpleRaConfiguration(
            final CredentialContext downstreamCredentials,
            final VerificationContext downstreamTrust,
            final CredentialContext upstreamCredentials,
            final VerificationContext upstreamTrust,
            final SignatureValidationCredentials enrollmentTrust) {
        return new Configuration() {
            @Override
            public CkgContext getCkgConfiguration(final String certProfile,
                    final int bodyType) {
                fail(String.format(
                        "getCkgConfiguration called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType)));
                return null;
            }

            @Override
            public CmpMessageInterface getDownstreamConfiguration(
                    final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getDownstreamConfiguration called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return new CmpMessageInterface() {

                    @Override
                    public VerificationContext getInputVerification() {
                        switch (certProfile) {
                        case "certProfileForKur":
                        case "certProfileForRr":
                            return enrollmentTrust;
                        }
                        return downstreamTrust;
                    }

                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return null;
                    }

                    @Override
                    public CredentialContext getOutputCredentials() {
                        try {
                            return downstreamCredentials;
                        } catch (final Exception e) {
                            throw new RuntimeException(e);
                        }
                    }

                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.keep;
                    }

                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isCacheExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isMessageTimeDeviationAllowed(
                            final long deviation) {
                        return true;
                    }
                };
            }

            @Override
            public VerificationContext getEnrollmentTrust(
                    final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getEnrollmentTrust called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return enrollmentTrust;
            }

            @Override
            public boolean getForceRaVerifyOnUpstream(final String certProfile,
                    final int bodyType) {
                LOGGER.debug(
                        "getForceRaVerifyOnUpstream called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return false;
            }

            @Override
            public InventoryInterface getInventory(final String certProfile,
                    final int bodyType) {
                LOGGER.debug(
                        "getInventory called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return new InventoryInterface() {

                    @Override
                    public CheckAndModifyResult checkAndModifyCertRequest(
                            final byte[] transactionID,
                            final String requesterDn, final byte[] certTemplate,
                            final String requestedSubjectDn) {
                        LOGGER.debug(
                                "checkAndModifyCertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID), requesterDn,
                                requestedSubjectDn);
                        return new CheckAndModifyResult() {

                            @Override
                            public byte[] getUpdatedCertTemplate() {
                                return null;
                            }

                            @Override
                            public boolean isGranted() {
                                return true;
                            }
                        };
                    }

                    @Override
                    public boolean checkP10CertRequest(
                            final byte[] transactionID,
                            final String requesterDn,
                            final byte[] pkcs10CertRequest,
                            final String requestedSubjectDn) {
                        fail(String.format(
                                "checkP10CertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID), requesterDn,
                                requestedSubjectDn));
                        return false;
                    }

                    @Override
                    public boolean learnEnrollmentResult(
                            final byte[] transactionID,
                            final byte[] certificate, final String serialNumber,
                            final String subjectDN, final String issuerDN) {
                        LOGGER.debug(
                                "learnEnrollmentResult called with transactionID: {}, serialNumber: {}, subjectDN: {}, issuerDN: {}",
                                new BigInteger(transactionID), serialNumber,
                                subjectDN, issuerDN);
                        return true;
                    }
                };
            }

            @Override
            public int getRetryAfterTimeInSeconds(final String certProfile,
                    final int bodyType) {
                LOGGER.debug(
                        "getRetryAfterTimeInSeconds called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return 1;
            }

            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    final String certProfile, final String infoTypeOid) {
                LOGGER.debug(
                        "getSupportMessageHandler called with certprofile: {}, infoTypeOid: {}",
                        certProfile, infoTypeOid);
                return null;
            }

            @Override
            public CmpMessageInterface getUpstreamConfiguration(
                    final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getUpstreamConfiguration called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return new CmpMessageInterface() {

                    @Override
                    public VerificationContext getInputVerification() {
                        return upstreamTrust;
                    }

                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return null;
                    }

                    @Override
                    public CredentialContext getOutputCredentials() {

                        try {
                            return upstreamCredentials;
                        } catch (final Exception e) {
                            throw new RuntimeException(e);
                        }
                    }

                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.reprotect;
                    }

                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isCacheExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isMessageTimeDeviationAllowed(
                            final long deviation) {
                        return true;
                    }
                };
            }

            @Override
            public boolean isRaVerifiedAcceptable(final String certProfile,
                    final int bodyType) {
                LOGGER.debug(
                        "isRaVerifiedAcceptable called with certprofile: {}, type: {}",
                        certProfile, MessageDumper.msgTypeAsString(bodyType));
                return false;
            }

        };
    }

    static public CertReqTemplateContent generateCertReqTemplateContent()
            throws IOException {
        final CertTemplateBuilder ctb = new CertTemplateBuilder();
        ctb.setSubject(new X500Name("CN=test"));
        final Controls controls = new Controls(new AttributeTypeAndValue(
                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.5.1.11"),
                new ASN1Integer(2048)));
        return new CertReqTemplateContent(ctb.build(),
                (ASN1Sequence) controls.toASN1Primitive());
    }

    static public ProtectionProvider getEePasswordbasedProtectionProvider()
            throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        if (eePasswordbasedProtectionProvider == null) {
            eePasswordbasedProtectionProvider = new ProtectionProviderFactory()
                    .createProtectionProvider(new SharedSecret(
                            "PASSWORDBASEDMAC", TestUtils.PASSWORD));
        }
        return eePasswordbasedProtectionProvider;
    }

    static public ProtectionProvider getEePbmac1ProtectionProvider()
            throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        if (eePbmac1ProtectionProvider == null) {
            eePbmac1ProtectionProvider =
                    new ProtectionProviderFactory().createProtectionProvider(
                            new SharedSecret("PBMAC1", TestUtils.PASSWORD));
        }
        return eePbmac1ProtectionProvider;
    }

    public static ProtectionProvider getEeSignaturebasedProtectionProvider()
            throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, KeyStoreException, Exception {
        if (eeSignaturebasedProtectionProvider == null) {
            eeSignaturebasedProtectionProvider = new ProtectionProviderFactory()
                    .createProtectionProvider(new TrustChainAndPrivateKey(
                            // "credentials/CMP_EE_Keystore_EdDSA.p12",
                            // "credentials/CMP_EE_Keystore_RSA.p12",
                            "credentials/CMP_EE_Keystore.p12",
                            TestUtils.PASSWORD_AS_CHAR_ARRAY));
        }
        return eeSignaturebasedProtectionProvider;
    }

    public static KeyPairGenerator getKeyGenerator() {
        if (keyGenerator == null)

        {
            try {
                //                keyGenerator = KeyPairGeneratorFactory
                //                        .getEcKeyPairGenerator("secp256r1");
                keyGenerator =
                        KeyPairGeneratorFactory.getRsaKeyPairGenerator(2048);
                //                keyGenerator = KeyPairGeneratorFactory
                //                        .getEdDsaKeyPairGenerator("Ed448");
            } catch (final GeneralSecurityException e) {
                fail(e.getMessage());
            }
        }
        return keyGenerator;
    }

    private ConfigurationFactory() {

    }

}
