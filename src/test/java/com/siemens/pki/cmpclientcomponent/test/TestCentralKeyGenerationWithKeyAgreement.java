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
package com.siemens.pki.cmpclientcomponent.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
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
import com.siemens.pki.cmpracomponent.cryptoservices.DataSignVerifier;
import com.siemens.pki.cmpracomponent.cryptoservices.DataSigner;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TestUtils;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RunWith(Parameterized.class)
public class TestCentralKeyGenerationWithKeyAgreement extends EnrollmentTestcaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_and_LRA_DOWNSTREAM_Root.pem";

    public static final String DEFAULT_KEY_AGREEMENT = "ECCDH_SHA256KDF";

    public static final String DEFAULT_KEY_ENCRYPTION = "AES256_WRAP";

    private static final Logger LOGGER = LoggerFactory.getLogger(TestCentralKeyGenerationWithKeyAgreement.class);
    public static Object[][] inputList = {
        {
            DEFAULT_KEY_AGREEMENT,
            DEFAULT_KEY_ENCRYPTION,
            X9ObjectIdentifiers.id_ecPublicKey.getId(),
            SECObjectIdentifiers.secp256r1.getId()
        },
        {DEFAULT_KEY_AGREEMENT, DEFAULT_KEY_ENCRYPTION, EdECObjectIdentifiers.id_Ed448.getId(), null},
        //
        {DEFAULT_KEY_AGREEMENT, DEFAULT_KEY_ENCRYPTION, EdECObjectIdentifiers.id_Ed25519.getId(), null},
        //
        {DEFAULT_KEY_AGREEMENT, DEFAULT_KEY_ENCRYPTION, PKCSObjectIdentifiers.rsaEncryption.getId(), null},
        //
        {DEFAULT_KEY_AGREEMENT, DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {DEFAULT_KEY_AGREEMENT, "2.16.840.1.101.3.4.1.5", null, null},
        //
        {DEFAULT_KEY_AGREEMENT, "2.16.840.1.101.3.4.1.25", null, null},
        //
        {DEFAULT_KEY_AGREEMENT, "2.16.840.1.101.3.4.1.45", null, null},
        //
        //
        {"1.3.132.1.11.0", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.11.1", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.11.2", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.11.3", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        //
        {"1.3.132.1.14.0", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.14.1", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.14.2", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.14.3", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        //
        {"1.3.132.1.15.0", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.15.1", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.15.2", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        {"1.3.132.1.15.3", DEFAULT_KEY_ENCRYPTION, null, null},
        //
        //
    };

    @Parameters(name = "{index}: keyAgreement=>{0}, keyEncryption=>{1}, EnrollmentKeyType=>{2}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        for (final Object[] aktInput : inputList) {
            final Object keyAgreement = aktInput[0];
            final Object keyEncryption = aktInput[1];
            final Object keyType = aktInput[2];
            final Object keyParam = aktInput[3];
            ret.add(new Object[] {
                keyAgreement, keyEncryption, keyType, keyParam, keyAgreement, keyEncryption, keyType, keyParam
            });
        }
        return ret;
    }

    private final String keyAgreementAlg;
    private final String keyEncryptionAlg;

    private TrustChainAndPrivateKey raCredentials;

    private final KeyPair keyPair;

    public TestCentralKeyGenerationWithKeyAgreement(
            final String keyAgreementAsString,
            final String keyEncryptionAsString,
            final String keyTypeAsString,
            final String keyParamAsString,
            final String keyAgreementOID,
            final String keyEncryptionOID,
            final String keyTypeOID,
            final String keyParamOID) {
        this.keyAgreementAlg = keyAgreementOID;
        this.keyEncryptionAlg = keyEncryptionOID;
        if (keyTypeOID != null) {
            PublicKey pubKey = new PublicKey() {
                private static final long serialVersionUID = 1L;

                @Override
                public byte[] getEncoded() {
                    try {
                        return new DERSequence(new ASN1Encodable[] {
                                    new AlgorithmIdentifier(
                                            new ASN1ObjectIdentifier(keyTypeOID),
                                            keyParamOID == null ? null : new ASN1ObjectIdentifier(keyParamOID)),
                                    new DERBitString(new byte[0])
                                })
                                .getEncoded();
                    } catch (IOException e) {
                        fail(e.getLocalizedMessage());
                        return null;
                    }
                }

                @Override
                public String getAlgorithm() {
                    return null;
                }

                @Override
                public String getFormat() {
                    return null;
                }
            };
            this.keyPair = new KeyPair(pubKey, null);
        } else {
            this.keyPair = null;
        }
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
                        return new CkgKeyAgreementContext() {

                            @Override
                            public String getKeyAgreementAlg() {
                                return keyAgreementAlg;
                            }

                            @Override
                            public String getKeyEncryptionAlg() {
                                return keyEncryptionAlg;
                            }

                            @Override
                            public PrivateKey getOwnPrivateKey() {
                                return raCredentials.getPrivateKey();
                            }

                            @Override
                            public PublicKey getOwnPublicKey() {
                                return raCredentials
                                        .getCertificateChain()
                                        .get(0)
                                        .getPublicKey();
                            }

                            @Override
                            public X509Certificate getRecipient(final X509Certificate protectingCertificate) {
                                return protectingCertificate;
                            }
                        };
                    }

                    @Override
                    public CkgKeyTransportContext getKeyTransportContext() {
                        fail("getKeyTransportContext");
                        return null;
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
                            final byte[] pkiMessage) {
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

    @Before
    public void setUp() throws Exception {
        raCredentials = new TrustChainAndPrivateKey(
                "credentials/CMP_LRA_DOWNSTREAM_Keystore.p12", TestUtils.PASSWORD_AS_CHAR_ARRAY);
        upstreamExchange = launchCmpCaAndRa(buildSignatureBasedDownstreamConfiguration());
    }

    /** Central Key Generation/Using Key Agreement Key Management Technique */
    @Test
    public void testCrWithKeyAgreement() throws Exception {
        final EnrollmentResult ret = getSignatureBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(PKIBody.TYPE_CERT_REQ, keyPair, null),
                        UPSTREAM_TRUST_PATH)
                .invokeEnrollment();
        assertNotNull(ret);
        // try to use received certificate and key
        final DataSigner testSigner = new DataSigner(ret.getPrivateKey(), ret.getEnrolledCertificate(), INTERFACE_NAME);
        final byte[] msgToSign = "Hello Signer, I am the message".getBytes();
        assertArrayEquals(
                msgToSign,
                DataSignVerifier.verifySignature(testSigner.signData(msgToSign).getEncoded()));
    }
}
