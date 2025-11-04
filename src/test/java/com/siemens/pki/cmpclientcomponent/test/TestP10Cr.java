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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestP10Cr extends EnrollmentTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestP10Cr.class);

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_and_LRA_DOWNSTREAM_Root.pem";

    public static Configuration buildSignatureBasedDownstreamConfiguration() throws Exception {
        final TrustChainAndPrivateKey downstreamCredentials =
                new TrustChainAndPrivateKey("credentials/CMP_LRA_DOWNSTREAM_Keystore.p12", "Password".toCharArray());
        final SignatureValidationCredentials downstreamTrust =
                new SignatureValidationCredentials("credentials/CMP_EE_Root.pem", null);
        final SignatureValidationCredentials enrollmentTrust =
                new SignatureValidationCredentials("credentials/ENROLL_Keystore.p12", "Password".toCharArray());

        return buildSimpleRaConfiguration(downstreamCredentials, downstreamTrust, enrollmentTrust);
    }

    public static Configuration buildSimpleRaConfiguration(
            final CredentialContext downstreamCredentials,
            final VerificationContext downstreamTrust,
            final SignatureValidationCredentials enrollmentTrust) {
        return new Configuration() {
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
            public int getDownstreamTimeout(final String certProfile, final int bodyType) {
                return 0;
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

                if ("refuseMeP10".equals(certProfile)) {
                    return new InventoryInterface() {
                        @Override
                        public boolean checkP10CertRequest(
                                byte[] transactionID,
                                String requesterDn,
                                byte[] pkcs10CertRequest,
                                String requestedSubjectDn,
                                byte[] pkiMessage) {
                            return false;
                        }
                    };
                }

                return new InventoryInterface() {

                    @Override
                    public CheckAndModifyResult checkAndModifyCertRequest(
                            final byte[] transactionID,
                            final String requesterDn,
                            final byte[] certTemplate,
                            final String requestedSubjectDn,
                            byte[] pkiMessage) {
                        fail(String.format(
                                "checkAndModifyCertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID),
                                requesterDn,
                                requestedSubjectDn));
                        return new CheckAndModifyResult() {

                            @Override
                            public byte[] getUpdatedCertTemplate() {
                                return null;
                            }

                            @Override
                            public boolean isGranted() {
                                return false;
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
                        LOGGER.debug(
                                "checkP10CertRequest called with transactionID: {}, requesterDn: {}, requestedSubjectDn: {}",
                                new BigInteger(transactionID),
                                requesterDn,
                                requestedSubjectDn);
                        return true;
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
                fail(String.format(
                        "getRetryAfterTimeInSeconds called with certprofile: {}, type: {}",
                        certProfile,
                        MessageDumper.msgTypeAsString(bodyType)));
                return 1;
            }

            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    final String certProfile, final String infoTypeOid) {
                fail(String.format(
                        "getSupportMessageHandler called with certprofile: {}, infoTypeOid: {}",
                        certProfile,
                        infoTypeOid));
                return null;
            }

            @Override
            public CmpMessageInterface getUpstreamConfiguration(final String certProfile, final int bodyType) {
                fail("getUpstreamConfiguration called");
                return null;
            }

            @Override
            public boolean isRaVerifiedAcceptable(final String certProfile, final int bodyType) {
                fail("isRaVerifiedAcceptable called");
                return false;
            }
        };
    }

    @Before
    public void setUp() throws Exception {
        final Configuration config = buildSignatureBasedDownstreamConfiguration();
        launchP10X509CaAndRa(config);
    }
    /**
     * A certificate from a legacy PKI using PKCS#10 request
     *
     * @throws Exception
     */
    @Test
    public void testP10Cr() throws Exception {
        final KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();
        final JcaPKCS10CertificationRequestBuilder p10Builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Subject"), keyPair.getPublic());
        final PrivateKey privateKey = keyPair.getPrivate();
        final ContentSigner signer =
                new JcaContentSignerBuilder(AlgorithmHelper.getSigningAlgNameFromKey(privateKey)).build(privateKey);
        p10Builder.build(signer).getEncoded();
        final EnrollmentResult ret = getSignatureBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(
                                PKIBody.TYPE_P10_CERT_REQ,
                                null,
                                p10Builder.build(signer).getEncoded()),
                        UPSTREAM_TRUST_PATH)
                .invokeEnrollment();
        assertNotNull(ret);
    }

    /**
     * A certificate from a legacy PKI using PKCS#10 request but refused by the inventory
     *
     * @throws Exception
     */
    @Test
    public void testRefusedP10Cr() throws Exception {
        final KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();
        final JcaPKCS10CertificationRequestBuilder p10Builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Subject"), keyPair.getPublic());
        final PrivateKey privateKey = keyPair.getPrivate();
        final ContentSigner signer =
                new JcaContentSignerBuilder(AlgorithmHelper.getSigningAlgNameFromKey(privateKey)).build(privateKey);
        p10Builder.build(signer).getEncoded();
        final EnrollmentResult ret = getSignatureBasedCmpClient(
                        "refuseMeP10",
                        getClientContext(
                                PKIBody.TYPE_P10_CERT_REQ,
                                null,
                                p10Builder.build(signer).getEncoded()),
                        UPSTREAM_TRUST_PATH)
                .invokeEnrollment();
        assertNull(ret);
    }
}
