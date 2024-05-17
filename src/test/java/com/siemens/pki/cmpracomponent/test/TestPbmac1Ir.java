/*
 *  Copyright (c) 2024 Siemens AG
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

public class TestPbmac1Ir extends PasswordEnrollmentTestcasebase {

    /**
     * Enrolling an End Entity to a New PKI/Using MAC-Based Protection for
     * Enrollment
     *
     * @throws Exception in case of error
     */
    @Test
    public void testPbmac1Ir() throws Exception {
        executeCrmfCertificateRequest(
                PKIBody.TYPE_INIT_REQ,
                PKIBody.TYPE_INIT_REP,
                ConfigurationFactory.getEePbmac1ProtectionProvider(),
                getEeClient());
    }
}
