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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.main.CmpClient;
import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface.ReprotectMode;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.PersistencyInterface;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.persistency.DefaultPersistencyImplementation;
import com.siemens.pki.cmpracomponent.test.framework.CmpCaMock;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.math.BigInteger;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestCrWithConfiguredRaRecipient extends EnrollmentTestcaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_Root.pem";

    private static final Logger LOGGER = LoggerFactory.getLogger(TestCrWithConfiguredRaRecipient.class);

    private static Configuration buildRaConfigurationWithRecipient(
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
                    public String getRecipient() {

                        return "CN=RecipientSetByRa";
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

        return buildRaConfigurationWithRecipient(
                downstreamCredentials,
                ReprotectMode.keep,
                downstreamTrust,
                upstreamCredentials,
                upstreamTrust,
                enrollmentTrust);
    }

    private CmpCaMock cmpCaMock;

    private UpstreamExchange upstreamRa;

    @Before
    public void setUp() throws Exception {
        cmpCaMock = new CmpCaMock("credentials/ENROLL_Keystore.p12", "credentials/CMP_CA_Keystore.p12");
        upstreamRa = launchCmpRa(buildSignatureBasedDownstreamConfiguration(), cmpCaMock::sendReceiveMessage);
    }

    @Test
    public void testCrWithRecipientByRa() throws Exception {
        final EnrollmentResult ret = new CmpClient(
                        "theCertProfileForOnlineEnrollment",
                        upstreamRa,
                        new CmpMessageInterface() {

                            final SignatureValidationCredentials upstreamTrust =
                                    new SignatureValidationCredentials(UPSTREAM_TRUST_PATH, null);

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
                                    return ConfigurationFactory.getEeSignaturebasedCredentials();
                                } catch (final Exception e) {
                                    fail(e.getLocalizedMessage());
                                    return null;
                                }
                            }

                            @Override
                            public String getRecipient() {
                                return "CN=RecipientSetByClient";
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
                                return deviation < 10;
                            }
                        },
                        getClientContext(
                                PKIBody.TYPE_CERT_REQ,
                                ConfigurationFactory.getKeyGenerator().generateKeyPair(),
                                null))
                .invokeEnrollment();
        assertNotNull(ret);
        assertEquals(
                "recipient",
                new GeneralName(new X500Name("CN=RecipientSetByRa")),
                cmpCaMock.getReceivedRequestAt(1).getHeader().getRecipient());
    }
}
