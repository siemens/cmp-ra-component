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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.main.CmpClient;
import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.test.framework.CmpCaMock;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Before;
import org.junit.Test;

public class TestCrWithConfiguredClientRecipient extends EnrollmentTestcaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_Root.pem";

    private CmpCaMock cmpCaMock;

    private UpstreamExchange upstreamRa;

    @Before
    public void setUp() throws Exception {
        cmpCaMock = new CmpCaMock("credentials/ENROLL_Keystore.p12", "credentials/CMP_CA_Keystore.p12");
        upstreamRa = launchCmpRa(
                ConfigurationFactory.buildSignatureBasedDownstreamConfiguration(), cmpCaMock::sendReceiveMessage);
    }

    @Test
    public void testCrWithRecipientByCient() throws Exception {
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
                new GeneralName(new X500Name("CN=RecipientSetByClient")),
                cmpCaMock.getReceivedRequestAt(1).getHeader().getRecipient());
    }
}
