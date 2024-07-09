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

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.cmpclientcomponent.main.CmpClient;
import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.KeyPairGeneratorFactory;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.junit.Before;
import org.junit.Test;

/**
 * use protection chains with different keytypes
 */
class SignatureBasedCrWithAllKeyTypesBase extends EnrollmentTestcaseBase {

    protected SignatureBasedCrWithAllKeyTypesBase(
            TrustChainAndPrivateKey fromClientToRa,
            TrustChainAndPrivateKey fromRaToClient,
            TrustChainAndPrivateKey enrollmentCredentials) {
        this.fromClientToRa = fromClientToRa;
        this.fromRaToClient = fromRaToClient;
        this.enrollmentCredentials = enrollmentCredentials;
    }

    private final TrustChainAndPrivateKey fromClientToRa;
    private final TrustChainAndPrivateKey fromRaToClient;
    private final TrustChainAndPrivateKey enrollmentCredentials;

    @Before
    public void setUp() throws Exception {
        launchCmpCaAndRa(enrollmentCredentials, new Configuration() {

            @Override
            public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
                return false;
            }

            @Override
            public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
                return new CmpMessageInterface() {

                    @Override
                    public boolean isMessageTimeDeviationAllowed(long deviation) {
                        return Math.abs(deviation) < 100;
                    }

                    @Override
                    public boolean isCacheExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return false;
                    }

                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.strip;
                    }

                    @Override
                    public CredentialContext getOutputCredentials() {
                        return null;
                    }

                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return null;
                    }

                    @Override
                    public VerificationContext getInputVerification() {
                        return null;
                    }
                };
            }

            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(String certProfile, String infoTypeOid) {
                return null;
            }

            @Override
            public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
                return 0;
            }

            @Override
            public InventoryInterface getInventory(String certProfile, int bodyType) {
                return null;
            }

            @Override
            public boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType) {
                return false;
            }

            @Override
            public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
                return enrollmentCredentials;
            }

            @Override
            public int getDownstreamTimeout(String certProfile, int bodyType) {
                return 0;
            }

            @Override
            public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
                return ConfigurationFactory.createSignatureBasedCmpMessageInterface(fromRaToClient, fromClientToRa);
            }

            @Override
            public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
                return null;
            }
        });
    }

    @Test
    public void testCr() throws Exception {
        final EnrollmentResult ret = getCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        new ClientContext() {

                            @Override
                            public EnrollmentContext getEnrollmentContext() {
                                return new EnrollmentContext() {

                                    @Override
                                    public KeyPair getCertificateKeypair() {
                                        return ConfigurationFactory.getKeyGenerator()
                                                .generateKeyPair();
                                    }

                                    @Override
                                    public byte[] getCertificationRequest() {
                                        return null;
                                    }

                                    @Override
                                    public VerificationContext getEnrollmentTrust() {
                                        return enrollmentCredentials;
                                    }

                                    @Override
                                    public int getEnrollmentType() {
                                        return PKIBody.TYPE_CERT_REQ;
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
                        },
                        ConfigurationFactory.createSignatureBasedCmpMessageInterface(fromClientToRa, fromRaToClient))
                .invokeEnrollment();
        assertNotNull(ret);
    }

    @Test
    public void testKemCr() throws Exception {
        final EnrollmentResult ret = getCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        new ClientContext() {

                            @Override
                            public EnrollmentContext getEnrollmentContext() {
                                return new EnrollmentContext() {

                                    @Override
                                    public KeyPair getCertificateKeypair() {
                                        try {
                                            return KeyPairGeneratorFactory.getGenericKeyPairGenerator(
                                                            NISTObjectIdentifiers.id_alg_ml_kem_512)
                                                    .generateKeyPair();
                                        } catch (GeneralSecurityException e) {
                                            fail(e.getLocalizedMessage());
                                            return null;
                                        }
                                    }

                                    @Override
                                    public byte[] getCertificationRequest() {
                                        return null;
                                    }

                                    @Override
                                    public VerificationContext getEnrollmentTrust() {
                                        return enrollmentCredentials;
                                    }

                                    @Override
                                    public int getEnrollmentType() {
                                        return PKIBody.TYPE_CERT_REQ;
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
                        },
                        ConfigurationFactory.createSignatureBasedCmpMessageInterface(fromClientToRa, fromRaToClient))
                .invokeEnrollment();
        assertNotNull(ret);
    }

    private CmpClient getCmpClient(
            String certProfile, ClientContext clientContext, CmpMessageInterface upstreamInterface) throws Exception {
        return new CmpClient(certProfile, getUpstreamExchange(), upstreamInterface, clientContext);
    }
}
