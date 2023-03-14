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
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.cryptoservices.CmsDecryptor;
import com.siemens.pki.cmpracomponent.protection.PasswordBasedMacProtection;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.SharedSecret;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RunWith(Parameterized.class)
public class TestCentralKeyGenerationWithPassword extends CkgOnlineEnrollmentTestcaseBase {

    private static final String DEFAULT_KEK_ALG = "AES256";
    private static final String DEFAULT_PRF = "SHA224";
    private static final int DEFAULT_ITERATIONCOUNT = 10_000;
    private static final Logger LOGGER = LoggerFactory.getLogger(TestCentralKeyGenerationWithPassword.class);
    public static Object[][] inputList = new Object[][] {
        //
        {DEFAULT_PRF, DEFAULT_ITERATIONCOUNT, DEFAULT_KEK_ALG},
        //
        {"SHA1", DEFAULT_ITERATIONCOUNT, DEFAULT_KEK_ALG},
        //
        {"SHA224", DEFAULT_ITERATIONCOUNT, DEFAULT_KEK_ALG},
        //
        {"SHA256", DEFAULT_ITERATIONCOUNT, DEFAULT_KEK_ALG},
        //
        {"SHA384", DEFAULT_ITERATIONCOUNT, DEFAULT_KEK_ALG},
        //
        {"SHA512", DEFAULT_ITERATIONCOUNT, DEFAULT_KEK_ALG},
        //
        {DEFAULT_PRF, 1, DEFAULT_KEK_ALG},
        //
        {DEFAULT_PRF, 100_000, DEFAULT_KEK_ALG},
        //
        {DEFAULT_PRF, DEFAULT_ITERATIONCOUNT, "AES128_CBC"},
        //
        {DEFAULT_PRF, DEFAULT_ITERATIONCOUNT, "AES192_CBC"},
        //
        {DEFAULT_PRF, DEFAULT_ITERATIONCOUNT, "AES256_CBC"},
        //
    };

    @Parameters(name = "{index}: prf=>{0}, iterationCount=>{1}, kek={2}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        for (final Object[] aktInput : inputList) {
            final Object prf = aktInput[0];
            final Object iterationCount = aktInput[1];
            final Object kek = aktInput[2];
            ret.add(new Object[] {prf, ((Integer) iterationCount).toString(), kek, prf, iterationCount, kek});
        }
        return ret;
    }

    private final String kekAlg;

    private final SharedSecret sharedSecret;

    public TestCentralKeyGenerationWithPassword(
            final String prfAsString,
            final String iterationCountAsString,
            final String kekAlgorithmOIDAsString,
            final String prf,
            final int iterationCount,
            final String kek)
            throws Exception {
        sharedSecret = new SharedSecret(
                "PBMAC1",
                "theSecret".getBytes(),
                "SHA256",
                "theSenderKid".getBytes(),
                CertUtility.generateRandomBytes(20),
                prf,
                iterationCount);
        this.kekAlg = kek;
        launchCmpCaAndRa(buildPasswordbasedDownstreamConfiguration());
    }

    public Configuration buildPasswordbasedDownstreamConfiguration() throws Exception {
        final VerificationContext downstreamTrust = new VerificationContext() {
            @Override
            public byte[] getSharedSecret(final byte[] senderKID) {
                return sharedSecret.getSharedSecret();
            }
        };
        final CredentialContext upstreamCredentials =
                new TrustChainAndPrivateKey("credentials/CMP_LRA_UPSTREAM_Keystore.p12", "Password".toCharArray());
        final VerificationContext upstreamTrust =
                new SignatureValidationCredentials("credentials/CMP_CA_Root.pem", null);
        final SignatureValidationCredentials enrollmentTrust =
                new SignatureValidationCredentials("credentials/ENROLL_Root.pem", null);

        final Configuration config = buildSimpleRaConfiguration(
                sharedSecret, downstreamTrust, upstreamCredentials, upstreamTrust, enrollmentTrust);
        return config;
    }

    /**
     * Central Key Generation/Using Password-Based Key Management Technique
     *
     * @throws Exception
     */
    @Test
    public void testCrWithPassword() throws Exception {
        final ProtectionProvider macBasedProvider = new PasswordBasedMacProtection(sharedSecret);

        executeCrmfCertificateRequestWithoutKey(
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                macBasedProvider,
                getEeClient(),
                new CmsDecryptor(null, null, "theSecret".toCharArray()));
    }

    protected Configuration buildSimpleRaConfiguration(
            final SharedSecretCredentialContext downstreamCredentials,
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
                        fail("getKeyTransportContext");
                        return null;
                    }

                    @Override
                    public CkgPasswordContext getPasswordContext() {
                        return new CkgPasswordContext() {

                            @Override
                            public SharedSecretCredentialContext getEncryptionCredentials() {
                                return downstreamCredentials;
                            }

                            @Override
                            public String getKekAlg() {
                                return kekAlg;
                            }
                        };
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
            public int getTransactionMaxLifetime(final String certProfile, final int bodyType) {
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
