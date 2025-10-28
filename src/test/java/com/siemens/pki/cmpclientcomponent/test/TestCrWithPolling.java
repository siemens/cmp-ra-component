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

import static org.junit.Assert.assertNotNull;

import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

public class TestCrWithPolling extends DelayedEnrollmentTescaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_and_LRA_DOWNSTREAM_Root.pem";

    @Before
    public void setUp() throws Exception {
        launchDelayedCmpCaAndRa(ConfigurationFactory.buildSignatureBasedDownstreamConfiguration());
    }

    @Test
    public void testCr() throws Exception {
        final EnrollmentResult ret = getSignatureBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(PKIBody.TYPE_CERT_REQ),
                        UPSTREAM_TRUST_PATH)
                .invokeEnrollment();
        assertNotNull(ret);
    }
}
