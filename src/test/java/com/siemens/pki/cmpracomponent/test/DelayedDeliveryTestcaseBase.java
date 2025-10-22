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
import static org.junit.Assert.fail;

import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.CmpCaMock;
import com.siemens.pki.cmpracomponent.test.framework.ConfigFileLoader;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.File;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.*;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DelayedDeliveryTestcaseBase {

    public static final File CONFIG_DIRECTORY = new File("./src/test/java/com/siemens/pki/cmpracomponent/test/config");

    private static final Logger LOGGER = LoggerFactory.getLogger(DelayedDeliveryTestcaseBase.class);
    private Function<PKIMessage, PKIMessage> eeClient;
    private CmpRaInterface raComponent;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        ConfigFileLoader.setConfigFileBase(CONFIG_DIRECTORY);
    }

    protected static PKIMessage executeRequestWithPolling(
            final int expectedWaitingResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient,
            final PKIMessage request)
            throws Exception {
        PKIMessage response = cmpClient.apply(request);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("test client got:\n" + MessageDumper.dumpPkiMessage(response));
        }
        final int responseType = response.getBody().getType();
        assertEquals("message type", expectedWaitingResponseMessageType, responseType);

        boolean pollingTriggered = false;
        switch (responseType) {
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP: {
                final CertResponse certResponseInBody =
                        ((CertRepMessage) response.getBody().getContent()).getResponse()[0];
                if (certResponseInBody.getStatus() != null
                        && certResponseInBody.getStatus().getStatus().intValue() == PKIStatus.WAITING) {
                    pollingTriggered = true;
                }
                break;
            }
            case PKIBody.TYPE_ERROR: {
                final ErrorMsgContent errorContent =
                        (ErrorMsgContent) response.getBody().getContent();
                if (errorContent.getPKIStatusInfo().getStatus().intValue() == PKIStatus.WAITING) {
                    pollingTriggered = true;
                }
                break;
            }
            default:
        }
        if (pollingTriggered) {
            // delayed delivery triggered, start polling
            for (; ; ) {
                final PKIMessage pollReq = PkiMessageGenerator.generateAndProtectMessage(
                        new HeaderProviderForTest(response.getHeader()),
                        protectionProvider,
                        PkiMessageGenerator.generatePollReq());
                response = cmpClient.apply(pollReq);
                if (response.getBody().getType() != PKIBody.TYPE_POLL_REP) {
                    break;
                }
                final ASN1Integer checkAfter =
                        ((PollRepContent) response.getBody().getContent()).getCheckAfter(0);
                Thread.sleep(1000L * checkAfter.getValue().longValue());
            }
        }
        return response;
    }

    protected Function<PKIMessage, PKIMessage> getEeClient() {
        return eeClient;
    }

    protected Function<PKIMessage, PKIMessage> launchDelayedCaAndRa(final Configuration config) throws Exception {

        final CmpCaMock caMock = new CmpCaMock("credentials/ENROLL_Keystore.p12", "credentials/CMP_CA_Keystore.p12");
        // delay request for 10 seconds before delivery to the CA
        final UpstreamExchange delayedTransport = (request, certProfile, bodyTypeOfFirstRequest) -> {
            new Timer()
                    .schedule(
                            new TimerTask() {

                                @Override
                                public void run() {
                                    try {
                                        raComponent.gotResponseAtUpstream(caMock.sendReceiveMessage(
                                                request, certProfile, bodyTypeOfFirstRequest));
                                    } catch (final Exception e) {
                                        fail(e.getMessage());
                                    }
                                }
                            },
                            10_000L);
            // trigger delayed delivery stuff in RA
            return null;
        };

        raComponent = CmpRaComponent.instantiateCmpRaComponent(config, delayedTransport);
        eeClient = req -> {
            try {
                return PKIMessage.getInstance(raComponent.processRequest(req.getEncoded()));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return eeClient;
    }
}
