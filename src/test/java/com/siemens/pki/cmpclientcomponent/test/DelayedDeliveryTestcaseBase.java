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
package com.siemens.pki.cmpclientcomponent.test;

import static org.junit.Assert.fail;

import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.test.framework.CmpCaMock;
import java.util.Timer;
import java.util.TimerTask;

public class DelayedDeliveryTestcaseBase extends CmpClientTestcaseBase {

    private CmpRaInterface raComponent;

    protected UpstreamExchange launchDelayedCmpCaAndRa(final Configuration config) throws Exception {

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
        upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
            try {
                return raComponent.processRequest(request);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return upstreamExchange;
    }
}
