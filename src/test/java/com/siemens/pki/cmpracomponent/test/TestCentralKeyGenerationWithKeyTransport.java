/*
 *  Copyright (c) 2021 Siemens AG
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

import static org.junit.Assert.fail;

import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CkgKeyAgreementContext;
import com.siemens.pki.cmpracomponent.configuration.CkgKeyTransportContext;
import com.siemens.pki.cmpracomponent.configuration.CkgPasswordContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CmsDecryptor;
import com.siemens.pki.cmpracomponent.protection.SignatureBasedProtection;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TestUtils;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestCentralKeyGenerationWithKeyTransport extends CkgOnlineEnrollmentTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestCentralKeyGenerationWithKeyTransport.class);
    private CmsDecryptor keyTransportDecryptor;

    private SignatureBasedProtection eeRsaCredentials;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        eeRsaCredentials = new SignatureBasedProtection(
                new TrustChainAndPrivateKey("credentials/CMP_EE_Keystore_RSA.p12", TestUtils.PASSWORD_AS_CHAR_ARRAY));
        keyTransportDecryptor =
                new CmsDecryptor(eeRsaCredentials.getEndCertificate(), eeRsaCredentials.getPrivateKey(), null);
        launchCmpCaAndRa(buildSignatureBasedDownstreamConfiguration());
    }

    /**
     * Central Key Generation/Using Key Transport Key Management Technique
     *
     * @throws Exception
     */
    @Test
    public void testCrWithKeyTransport() throws Exception {
        executeCrmfCertificateRequestWithoutKey(
                PKIBody.TYPE_CERT_REQ, PKIBody.TYPE_CERT_REP, eeRsaCredentials, getEeClient(), keyTransportDecryptor);
    }

    /**
     * Central Key Generation/Using Key Transport Key Management Technique
     *
     * @throws Exception
     */
    @Test
    public void testIrWithKeyTransport() throws Exception {
        executeCrmfCertificateRequestWithoutKey(
                PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_INIT_REP, eeRsaCredentials, getEeClient(), keyTransportDecryptor);
    }

    /**
     * Central Key Generation/Using Key Transport Key Management Technique
     *
     * @throws Exception
     */
    @Test
    public void testKurWithKeyTransport() throws Exception {
        executeCrmfCertificateRequestWithoutKey(
                PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_INIT_REP, eeRsaCredentials, getEeClient(), keyTransportDecryptor);
    }

    private Configuration buildSignatureBasedDownstreamConfiguration() throws Exception {
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
                downstreamCredentials, downstreamTrust, upstreamCredentials, upstreamTrust, enrollmentTrust);
    }

    private Configuration buildSimpleRaConfiguration(
            final CredentialContext downstreamCredentials,
            final VerificationContext downstreamTrust,
            final CredentialContext upstreamCredentials,
            final VerificationContext upstreamTrust,
            final SignatureValidationCredentials enrollmentTrust) {
        return new Configuration() {
            @Override
            public CkgContext getCkgConfiguration(final String certProfile, final int bodyType) {
                LOGGER.debug(
                        "getCkgConfiguration called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType));
                return new CkgContext() {

                    @Override
                    public CkgKeyAgreementContext getKeyAgreementContext() {
                        fail("getKeyAgreementContext");
                        return null;
                    }

                    @Override
                    public CkgKeyTransportContext getKeyTransportContext() {
                        return new CkgKeyTransportContext() {
                            @Override
                            public X509Certificate getRecipient(final X509Certificate protectingCertificate) {
                                return protectingCertificate;
                            }
                        };
                    }

                    @Override
                    public CkgPasswordContext getPasswordContext() {
                        fail("getPasswordContext");
                        return null;
                    }

                    @Override
                    public SignatureCredentialContext getSigningCredentials() {
                        try {
                            return new TrustChainAndPrivateKey(
                                    "credentials/CMP_LRA_DOWNSTREAM_Keystore.p12", "Password".toCharArray());
                        } catch (final Exception e) {
                            fail(e.getMessage());
                            return null;
                        }
                    }
                };
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
            public int getDownstreamExpirationTime(final String certProfile, final int bodyType) {
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
                            final String requestedSubjectDn) {
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
                            final String requestedSubjectDn) {
                        LOGGER.debug(
                                "checkP10CertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID),
                                requesterDn,
                                requestedSubjectDn);
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
                return true;
            }
        };
    }
}
