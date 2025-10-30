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
package com.siemens.pki.cmpclientcomponent.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.configuration.ClientAttestationContext;
import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface.ReprotectMode;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.GetFreshRatNonceHandler;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.PersistencyInterface;
import com.siemens.pki.cmpracomponent.configuration.RatVerifierAdapter;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.persistency.DefaultPersistencyImplementation;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.verifieradapter.asn1.AttestationObjectIdentifiers;
import com.siemens.pki.verifieradapter.asn1.AttestationResult;
import com.siemens.pki.verifieradapter.asn1.AttestationResultBundle;
import com.siemens.pki.verifieradapter.asn1.EvidenceStatement;
import com.siemens.pki.verifieradapter.asn1.NonceResponseValue.NonceResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestCrWithRAT extends EnrollmentTestcaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_and_LRA_DOWNSTREAM_Root.pem";

    private static final Logger LOGGER = LoggerFactory.getLogger(TestCrWithRAT.class);

    private static Configuration buildSignatureBasedDownstreamConfiguration() throws Exception {
        final TrustChainAndPrivateKey downstreamCredentials =
                new TrustChainAndPrivateKey("credentials/CMP_LRA_DOWNSTREAM_Keystore.p12", "Password".toCharArray());
        final SignatureValidationCredentials downstreamTrust =
                new SignatureValidationCredentials("credentials/CMP_EE_Root.pem", null);
        final TrustChainAndPrivateKey upstreamCredentials =
                new TrustChainAndPrivateKey("credentials/CMP_LRA_UPSTREAM_Keystore.p12", "Password".toCharArray());
        final SignatureValidationCredentials upstreamTrust =
                new SignatureValidationCredentials("credentials/CMP_CA_Root.pem", null);
        final SignatureValidationCredentials enrollmentTrust =
                new SignatureValidationCredentials("credentials/ENROLL_Root.pem", null);

        return buildSimpleRaConfiguration(
                downstreamCredentials,
                ReprotectMode.keep,
                downstreamTrust,
                upstreamCredentials,
                upstreamTrust,
                enrollmentTrust);
    }

    private static Configuration buildSimpleRaConfiguration(
            final CredentialContext downstreamCredentials,
            ReprotectMode reprotectMode,
            final VerificationContext downstreamTrust,
            final CredentialContext upstreamCredentials,
            final VerificationContext upstreamTrust,
            final SignatureValidationCredentials enrollmentTrust) {
        return new Configuration() {
            PersistencyInterface persistency = new DefaultPersistencyImplementation(5000);

            @Override
            public CkgContext getCkgConfiguration(final String certProfile, final int bodyType) {
                fail(String.format(
                        "getCkgConfiguration called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType)));
                return null;
            }

            @Override
            public CmpMessageInterface getDownstreamConfiguration(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getDownstreamConfiguration called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
                return new CmpMessageInterface() {

                    @Override
                    public VerificationContext getInputVerification() {
                        if (certProfile != null) {
                            switch (certProfile) {
                                case "certProfileForKur":
                                case "certProfileForRr":
                                    return enrollmentTrust;
                            }
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
                        return reprotectMode;
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
                    public boolean isMessageTimeDeviationAllowed(final long deviation) {
                        return true;
                    }
                };
            }

            @Override
            public int getDownstreamTimeout(final String certProfile, final int bodyType) {
                return 10;
            }

            @Override
            public VerificationContext getEnrollmentTrust(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getEnrollmentTrust called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
                return enrollmentTrust;
            }

            @Override
            public boolean getForceRaVerifyOnUpstream(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getForceRaVerifyOnUpstream called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
                return false;
            }

            @Override
            public RatVerifierAdapter getVerifierAdapter(String certProfile, int bodyType) {
                return new RatVerifierAdapter() {

                    @Override
                    public byte[] processRatVerification(byte[] transactionId, byte[] evidence) {
                        LOGGER.debug(
                                "processRatVerification called with certprofile: {}, type: {}",
                                certProfile,
                                MessageDumper.msgTypeAsString(bodyType));

                        EvidenceStatement evidenceStatement = EvidenceStatement.getInstance(evidence);
                        assertNotNull(evidenceStatement.getHint());
                        assertNotNull(evidenceStatement.getStmt());

                        try {
                            return new AttestationResult(
                                            evidenceStatement.getType().branch("99"),
                                            new DERUTF8String("attestation result stm"))
                                    .getEncoded();
                        } catch (IOException e) {
                            fail(e.getMessage());
                            return null;
                        }
                    }

                    @Override
                    public NonceResponseRet generateNonce(
                            byte[] transactionId,
                            BigInteger len,
                            String type,
                            String hint,
                            byte[] encodedNonceRequest) {
                        LOGGER.debug(
                                "generateNonce called with certprofile: {}, type: {}",
                                certProfile,
                                MessageDumper.msgTypeAsString(bodyType));
                        return new NonceResponseRet() {

                            @Override
                            public byte[] getNonce() {
                                return CertUtility.generateRandomBytes(len.intValue());
                            }

                            @Override
                            public Integer getExpiry() {
                                return 999;
                            }

                            @Override
                            public String getHint() {
                                return "responded hint: " + hint;
                            }

                            @Override
                            public String getType() {
                                return new ASN1ObjectIdentifier("1.7.8.9").getId();
                            }
                        };
                    }
                };
            }

            @Override
            public InventoryInterface getInventory(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getInventory called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
                return new InventoryInterface() {

                    @Override
                    public CheckAndModifyResult checkAndModifyCertRequest(
                            final byte[] transactionID,
                            final String requesterDn,
                            final byte[] certTemplate,
                            final String requestedSubjectDn,
                            byte[] pkiMessage) {
                        LOGGER.debug(
                                "checkAndModifyCertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID),
                                requesterDn,
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
                            final String requestedSubjectDn,
                            byte[] pkiMessage) {
                        fail(String.format(
                                "checkP10CertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID),
                                requesterDn,
                                requestedSubjectDn));
                        return false;
                    }

                    @Override
                    public boolean learnEnrollmentResult(
                            final byte[] transactionID,
                            final byte[] certificate,
                            final String serialNumber,
                            final String subjectDN,
                            final String issuerDN) {
                        LOGGER.debug(
                                "learnEnrollmentResult called with transactionID: {}, serialNumber: {}, subjectDN: {}, issuerDN: {}",
                                new BigInteger(transactionID),
                                serialNumber,
                                subjectDN,
                                issuerDN);
                        return true;
                    }
                };
            }

            @Override
            public PersistencyInterface getPersistency() {
                return persistency;
            }

            @Override
            public int getRetryAfterTimeInSeconds(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getRetryAfterTimeInSeconds called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
                return 1;
            }

            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    final String certProfile, final String infoTypeOid) {
                LOGGER.debug(
                        "getSupportMessageHandler called with certprofile: {}, infoTypeOid: {}",
                        certProfile,
                        infoTypeOid);
                if (AttestationObjectIdentifiers.id_it_NonceRequest.getId().equalsIgnoreCase(infoTypeOid)) {
                    return new GetFreshRatNonceHandler() {};
                }
                return null;
            }

            @Override
            public CmpMessageInterface getUpstreamConfiguration(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getUpstreamConfiguration called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
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
                    public boolean isMessageTimeDeviationAllowed(final long deviation) {
                        return true;
                    }
                };
            }

            @Override
            public boolean isRaVerifiedAcceptable(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "isRaVerifiedAcceptable called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
                return false;
            }
        };
    }

    @Override
    ClientContext getClientContext(final int enrollmentType, KeyPair keyPair, byte[] certificationRequest) {
        return new ClientContext() {

            @Override
            public ClientAttestationContext getAttestationContext() {
                return new ClientAttestationContext() {

                    @Override
                    public String getNonceRequestHint() {
                        return "nonce hint";
                    }

                    @Override
                    public String getNonceRequestType() {
                        return "1.9.8.7.6";
                    }

                    @Override
                    public BigInteger getNonceRequestLen() {
                        return new BigInteger("16");
                    }

                    @Override
                    public Certificate[] getEvidenceBundleCerts() {
                        // just provide some certificates
                        final SignatureValidationCredentials enrollmentTrust =
                                new SignatureValidationCredentials("credentials/ENROLL_Root.pem", null);
                        final Collection<X509Certificate> trustedCertificates =
                                enrollmentTrust.getTrustedCertificates();
                        Certificate[] ret = new Certificate[trustedCertificates.size()];
                        int i = 0;
                        for (X509Certificate akt : trustedCertificates) {
                            try {
                                ret[i++] = Certificate.getInstance(akt.getEncoded());
                            } catch (CertificateEncodingException e) {
                                fail(e.getLocalizedMessage());
                            }
                        }
                        return ret;
                    }

                    @Override
                    public byte[] getEvidenceStatement(byte[] attestationNonce) {

                        NonceResponse nonceResponse = NonceResponse.getInstance(attestationNonce);
                        assertNotNull(nonceResponse.getExpiry());
                        assertNotNull(nonceResponse.getHint());
                        try {
                            return new EvidenceStatement(
                                            nonceResponse.getType().branch("88"),
                                            new DERUTF8String("evidence statement"),
                                            new DERIA5String("evidence hint"))
                                    .getEncoded();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                };
            }

            @Override
            public EnrollmentContext getEnrollmentContext() {
                return new EnrollmentContext() {

                    @Override
                    public KeyPair getCertificateKeypair() {
                        return keyPair;
                    }

                    @Override
                    public byte[] getCertificationRequest() {
                        return certificationRequest;
                    }

                    @Override
                    public VerificationContext getEnrollmentTrust() {
                        return enrollmentCredentials;
                    }

                    @Override
                    public int getEnrollmentType() {
                        return enrollmentType;
                    }

                    @Override
                    public List<TemplateExtension> getExtensions() {
                        return null;
                    }

                    @Override
                    public X509Certificate getOldCert() {
                        return null;
                    }

                    @Override
                    public boolean getRequestImplictConfirm() {
                        return false;
                    }

                    @Override
                    public String getSubject() {
                        return "CN=Subject";
                    }
                };
            }

            @Override
            public RevocationContext getRevocationContext() {
                fail("getRevocationContext");
                return null;
            }
        };
    }

    @Before
    public void setUp() throws Exception {
        launchCmpCaAndRa(buildSignatureBasedDownstreamConfiguration());
    }

    @Test
    public void testCr() throws Exception {
        final EnrollmentResult ret = getSignatureBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(
                                PKIBody.TYPE_CERT_REQ,
                                ConfigurationFactory.getKeyGenerator().generateKeyPair(),
                                null),
                        UPSTREAM_TRUST_PATH)
                .invokeEnrollment();
        final ASN1OctetString extValue = ASN1OctetString.getInstance(
                ret.getEnrolledCertificate().getExtensionValue(AttestationObjectIdentifiers.id_aa_ar.getId()));
        final AttestationResultBundle attestationResultBundle =
                AttestationResultBundle.getInstance(extValue.getOctets());
        assertNotNull(attestationResultBundle);
        assertNotNull(attestationResultBundle.getCerts());
        for (AttestationResult result : attestationResultBundle.getResults()) {
            assertNotNull(result.getType());
            assertNotNull(result.getStmt());
        }
    }
}
