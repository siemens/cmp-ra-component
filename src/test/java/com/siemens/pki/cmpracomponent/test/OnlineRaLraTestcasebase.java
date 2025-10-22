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
package com.siemens.pki.cmpracomponent.test;

import static org.junit.Assert.fail;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface.ReprotectMode;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import java.io.IOException;
import java.util.function.Function;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.Before;
import org.junit.Test;

public class OnlineRaLraTestcasebase extends OnlineEnrollmentTestcaseBase {

    private Function<PKIMessage, PKIMessage> eeClient;

    @Override
    public Function<PKIMessage, PKIMessage> getEeClient() {
        return eeClient;
    }

    @Before
    public void setUp() throws Exception {
        launchCmpCaAndRaAndLra(buildRaConfig(), ConfigurationFactory.buildSignatureBasedDownstreamConfiguration());
    }

    /**
     * Enrolling an End Entity to a Known PKI
     *
     * @throws Exception
     */
    @Test
    public void testCr() throws Exception {
        executeCrmfCertificateRequest(
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                getEeClient());
    }

    private Configuration buildRaConfig() throws Exception {

        final TrustChainAndPrivateKey downStreamCredentials =
                new TrustChainAndPrivateKey("credentials/CMP_CA_Keystore.p12", "Password".toCharArray());
        final SignatureValidationCredentials downstreamTrust = new SignatureValidationCredentials(
                "credentials/CMP_LRA_UPSTREAM_Keystore.p12", "Password".toCharArray());
        final TrustChainAndPrivateKey upstreamCredentials =
                new TrustChainAndPrivateKey("credentials/CMP_LRA_UPSTREAM_Keystore.p12", "Password".toCharArray());
        final SignatureValidationCredentials upstreamTrust =
                new SignatureValidationCredentials("credentials/CMP_CA_Root.pem", null);
        final SignatureValidationCredentials enrollmentTrust =
                new SignatureValidationCredentials("credentials/ENROLL_Root.pem", null);

        return ConfigurationFactory.buildSimpleRaConfiguration(
                downStreamCredentials,
                ReprotectMode.keep,
                downstreamTrust,
                false,
                upstreamCredentials,
                upstreamTrust,
                enrollmentTrust);
    }

    @Override
    protected Function<PKIMessage, PKIMessage> launchCmpCaAndRaAndLra(
            final Configuration raConfig, final Configuration lraConfig) throws Exception {
        final Function<PKIMessage, PKIMessage> ra = launchCmpCaAndRa(raConfig);
        final CmpRaInterface lra = CmpRaComponent.instantiateCmpRaComponent(lraConfig, (x, y, z) -> {
            try {
                return ra.apply(PKIMessage.getInstance(x)).getEncoded();
            } catch (final IOException e) {
                fail(e.getMessage());
                return null;
            }
        });
        eeClient = req -> {
            try {
                return PKIMessage.getInstance(lra.processRequest(req.getEncoded()));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return eeClient;
    }
}
