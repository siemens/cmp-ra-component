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

import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Test;

public class TestCrWithPolling extends DelayedEnrollmentTescaseBase {

    /**
     * Handling Delayed Delivery/Enrolling an End Entity to a Known PKI
     *
     * @throws Exception
     */
    @Test
    public void testCrWithPolling() throws Exception {
        executeDelayedCertificateRequest(
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                getEeClient());
    }

    /**
     * Handling Delayed Delivery/Enrolling an End Entity to a Known PKI
     *
     * @throws Exception
     */
    @Test
    public void testCrWithPollingAndExpireingTransaction() throws Exception {
        executeDelayedCertificateRequest(
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                getEeClient(),
                20,
                PKIBody.TYPE_ERROR);
    }
}
