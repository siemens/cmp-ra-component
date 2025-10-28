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
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.TcAlgs;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * enroll certificates of different keytypes
 */
@RunWith(Parameterized.class)
public class TestEnrollmentForAllKeyTypes extends EnrollmentTestcaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_CA_and_LRA_DOWNSTREAM_Root.pem";

    @Parameters(name = "{0}")
    public static Iterable<Object[]> data() throws GeneralSecurityException {
        List<Object[]> ret = new ArrayList<Object[]>();
        ret.addAll(TcAlgs.getKemAlgorithms());
        ret.addAll(TcAlgs.getCompositeAlgorithms());
        ret.addAll(TcAlgs.getPqSignatureAlgorithms());
        ret.addAll(TcAlgs.getClassicSignatureAlgorithms());
        return ret;
    }

    private KeyPairGenerator kp;

    public TestEnrollmentForAllKeyTypes(String description, KeyPairGenerator kp) {
        this.kp = kp;
    }

    @Before
    public void setUp() throws Exception {
        launchCmpCaAndRa(ConfigurationFactory.buildSignatureBasedDownstreamConfiguration());
    }

    @Test
    public void testCr() throws Exception {
        final EnrollmentResult ret = getSignatureBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(PKIBody.TYPE_CERT_REQ, kp.generateKeyPair(), null),
                        UPSTREAM_TRUST_PATH)
                .invokeEnrollment();
        assertNotNull(ret);
    }
}
