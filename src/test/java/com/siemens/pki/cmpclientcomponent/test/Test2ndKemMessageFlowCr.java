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
import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class Test2ndKemMessageFlowCr extends EnrollmentTestcaseBase {

    private static Object[][] inputList = {
        //
        {ISOIECObjectIdentifiers.id_kem_rsa.getId()}, {"RSA"},
        //
        {BCObjectIdentifiers.kyber512.getId()}, {"KYBER"}
    };

    @Parameters(name = "{index}: KEM alg=>{0}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        Collections.addAll(ret, inputList);
        return ret;
    }

    private final KeyPair kemKeyPair;

    public Test2ndKemMessageFlowCr(String kemAlg) throws GeneralSecurityException {
        kemKeyPair = KemHandler.createKemHandler(kemAlg).generateNewKeypair();
    }

    @Before
    public void setUp() throws Exception {
        launchCmpCaAndRa(ConfigurationFactory.buildKemBasedDownstreamConfiguration(kemKeyPair.getPrivate()));
    }

    @Test
    public void testCr() throws Exception {
        final EnrollmentResult ret = getKemBasedCmpClient(
                        "theCertProfileForOnlineEnrollment",
                        getClientContext(
                                PKIBody.TYPE_CERT_REQ,
                                ConfigurationFactory.getKeyGenerator().generateKeyPair(),
                                null),
                        kemKeyPair.getPublic())
                .invokeEnrollment();
        assertNotNull(ret);
    }
}
