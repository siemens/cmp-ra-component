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
package com.siemens.pki.cmpracomponent.test;

import static org.junit.Assert.assertEquals;

import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.EnrollmentResult;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.security.KeyPair;
import java.util.function.Function;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DelayedEnrollmentTescaseBase extends DelayedDeliveryTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(DelayedEnrollmentTescaseBase.class);

    protected static EnrollmentResult executeDelayedCertificateRequest(
            final int requestMesssageType,
            final int expectedWaitingResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient)
            throws Exception {
        return executeDelayedCertificateRequest(
                requestMesssageType,
                expectedWaitingResponseMessageType,
                protectionProvider,
                cmpClient,
                0,
                PKIBody.TYPE_CONFIRM);
    }

    protected static EnrollmentResult executeDelayedCertificateRequest(
            final int requestMesssageType,
            final int expectedWaitingResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient,
            final int delayBeforeConfirm,
            final int confirmingBodyType)
            throws Exception {
        final KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(
                        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(new X500Name("CN=Subject"));

        final PKIBody crBody =
                PkiMessageGenerator.generateIrCrKurBody(requestMesssageType, ctb.build(), null, keyPair.getPrivate());

        final PKIMessage cr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("theCertProfileForDelayedEnrollment"), protectionProvider, crBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = DelayedDeliveryTestcaseBase.executeRequestWithPolling(
                expectedWaitingResponseMessageType, protectionProvider, cmpClient, cr);
        final CMPCertificate enrolledCertificate = ((CertRepMessage)
                        crResponse.getBody().getContent())
                .getResponse()[0]
                .getCertifiedKeyPair()
                .getCertOrEncCert()
                .getCertificate();
        Thread.sleep(delayBeforeConfirm * 1000L);
        final PKIMessage certConf = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(crResponse.getHeader()),
                protectionProvider,
                PkiMessageGenerator.generateCertConfBody(enrolledCertificate));

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
        }
        final PKIMessage pkiConf = cmpClient.apply(certConf);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
        }
        assertEquals("message type", confirmingBodyType, pkiConf.getBody().getType());

        return new EnrollmentResult(enrolledCertificate, keyPair.getPrivate());
    }

    @Before
    public void setUp() throws Exception {
        final Configuration config = ConfigurationFactory.buildSignatureBasedDownstreamConfiguration();
        launchDelayedCaAndRa(config);
    }
}
