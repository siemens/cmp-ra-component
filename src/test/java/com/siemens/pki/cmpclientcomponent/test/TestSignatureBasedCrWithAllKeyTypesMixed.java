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

import com.siemens.pki.cmpracomponent.cryptoservices.KeyPairGeneratorFactory;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * use protection chains with mixed keytypes
 */
@RunWith(Parameterized.class)
public class TestSignatureBasedCrWithAllKeyTypesMixed extends SignatureBasedCrWithAllKeyTypesBase {

    @Parameters(name = "{0}")
    public static Iterable<Object[]> data() throws GeneralSecurityException {
        KeyPairGenerator pqKpg =
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(BCObjectIdentifiers.sphincsPlus_sha2_128f);
        KeyPairGenerator rsaKpg = KeyPairGeneratorFactory.getRsaKeyPairGenerator(1024);
        KeyPairGenerator ecKpg = KeyPairGeneratorFactory.getEcKeyPairGenerator("secp256r1");
        KeyPairGenerator edKpg = KeyPairGeneratorFactory.getEdDsaKeyPairGenerator("Ed448");
        KeyPairGenerator compKpg =
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);

        return Arrays.asList(new Object[][] {
            //
            {"EC-COMP-RSA", new KeyPairGenerator[] {ecKpg, compKpg, rsaKpg}},
            {"EC-ED-COMP", new KeyPairGenerator[] {ecKpg, edKpg, compKpg}},
            {"PQ-RSA-EC", new KeyPairGenerator[] {pqKpg, rsaKpg, ecKpg}},
            {"RSA-PQ-EC", new KeyPairGenerator[] {rsaKpg, pqKpg, ecKpg}},
            {"ED-PQ-EC", new KeyPairGenerator[] {edKpg, pqKpg, ecKpg}},
        });
    }

    public TestSignatureBasedCrWithAllKeyTypesMixed(String description, KeyPairGenerator... kps) throws Exception {
        super(
                new TrustChainAndPrivateKey("CLIENT", false, kps),
                new TrustChainAndPrivateKey("RA_DOWN", false, kps),
                new TrustChainAndPrivateKey("ENROLL_", true, kps));
    }
}
