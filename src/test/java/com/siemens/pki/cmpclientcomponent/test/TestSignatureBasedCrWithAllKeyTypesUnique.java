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
package com.siemens.pki.cmpclientcomponent.test;

import com.siemens.pki.cmpracomponent.test.framework.TcAlgs;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * use protection chains with unique keytype
 */
@RunWith(Parameterized.class)
public class TestSignatureBasedCrWithAllKeyTypesUnique extends SignatureBasedCrWithAllKeyTypesBase {
    public TestSignatureBasedCrWithAllKeyTypesUnique(String description, KeyPairGenerator kp) throws Exception {
        super(
                new TrustChainAndPrivateKey("CLIENT", false, null, kp, kp, kp),
                new TrustChainAndPrivateKey("RA_DOWN", false, null, kp, kp, kp),
                new TrustChainAndPrivateKey("ENROLL", true, null, kp, kp, kp));
    }

    @Parameters(name = "{0}")
    public static Iterable<Object[]> data() throws GeneralSecurityException {
        List<Object[]> ret = new ArrayList<Object[]>();
        ret.addAll(TcAlgs.getCompositeAlgorithms());
        ret.addAll(TcAlgs.getPqSignatureAlgorithms());
        ret.addAll(TcAlgs.getClassicSignatureAlgorithms());
        return ret;
    }
}
