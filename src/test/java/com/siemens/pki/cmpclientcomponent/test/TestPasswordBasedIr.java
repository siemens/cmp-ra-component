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

import com.siemens.pki.cmpclientcomponent.main.CmpClient.EnrollmentResult;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SharedSecret;
import com.siemens.pki.cmpracomponent.test.framework.TestUtils;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

public class TestPasswordBasedIr extends EnrollmentTestcaseBase {

    @Before
    public void setUp() throws Exception {
        final Configuration config = ConfigurationFactory.buildPasswordbasedDownstreamConfiguration();
        launchCmpCaAndRa(config);
    }

    @Test
    public void testIr() throws Exception {
        final EnrollmentResult ret = getPasswordBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(
                                PKIBody.TYPE_CERT_REQ,
                                ConfigurationFactory.getKeyGenerator().generateKeyPair(),
                                null),
                        new SharedSecret("PASSWORDBASEDMAC", TestUtils.PASSWORD),
                        null)
                .invokeEnrollment();
        assertNotNull(ret);
    }

    /**
     * Enrolling an End Entity to a New PKI/Using MAC-Based Protection for
     * Enrollment
     *
     * @throws Exception in case of error
     */
    @Test
    public void testPbmac1Ir() throws Exception {
        final EnrollmentResult ret = getPasswordBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(
                                PKIBody.TYPE_CERT_REQ,
                                ConfigurationFactory.getKeyGenerator().generateKeyPair(),
                                null),
                        new SharedSecret("PBMAC1", TestUtils.PASSWORD),
                        null)
                .invokeEnrollment();
        assertNotNull(ret);
    }
}
