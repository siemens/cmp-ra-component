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

import static org.junit.Assert.assertEquals;

import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.EnrollmentResult;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.util.MessageDumper;

public class TestSignaturebasedRr extends SignatureEnrollmentTestcaseBase {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(TestSignaturebasedRr.class);

    /**
     * Revoking a Certificate
     *
     * @throws Exception
     */
    @Test
    public void testRr() throws Exception {
        final EnrollmentResult certificateToRevoke =
                executeCrmfCertificateRequest(PKIBody.TYPE_CERT_REQ,
                        PKIBody.TYPE_CERT_REP,
                        ConfigurationFactory
                                .getEeSignaturebasedProtectionProvider(),
                        getEeClient());
        final ProtectionProvider rrProtector = getEnrollmentCredentials()
                .setEndEntityToProtect(certificateToRevoke.getCertificate(),
                        certificateToRevoke.getPrivateKey());
        final PKIMessage rr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("certProfileForRr"), rrProtector,
                PkiMessageGenerator
                        .generateRrBody(certificateToRevoke.getCertificate()));
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(rr));
        }
        final PKIMessage rrResponse = getEeClient().apply(rr);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(rrResponse));
        }
        assertEquals("message type", PKIBody.TYPE_REVOCATION_REP,
                rrResponse.getBody().getType());

    }
}
