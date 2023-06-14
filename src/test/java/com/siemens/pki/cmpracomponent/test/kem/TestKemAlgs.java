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
package com.siemens.pki.cmpracomponent.test.kem;

import static org.junit.Assert.assertTrue;

import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestKemAlgs {

    private static Object[][] inputList = {
        //
        {"RSA"},
        {ISOIECObjectIdentifiers.id_kem_rsa.getId()},
        //
        {"Kyber"},
        {BCObjectIdentifiers.kyber512.getId()},
        {BCObjectIdentifiers.kyber1024_aes.getId()},
        //
        {"CMCE"},
        //
        {"Frodo"},
        //
        {"SABER"},
        //
        {"NTRU"},
        {BCObjectIdentifiers.ntruhps2048509.getId()},
        {BCObjectIdentifiers.pqc_kem_ntru.getId()},
        //
        {"BIKE"},
        //
        {"HQC"}
    };

    @Parameters(name = "{index}: KEM alg=>{0}")
    public static List<Object[]> data() {
        final List<Object[]> ret = new ArrayList<>(inputList.length);
        Collections.addAll(ret, inputList);
        return ret;
    }

    private final String kemAlgorithm;

    public TestKemAlgs(String kemAlgorithm) {
        this.kemAlgorithm = kemAlgorithm;
    }

    @Test
    public void testOneKem()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {

        final KemHandler kemHandler = KemHandler.createKemHandler(kemAlgorithm);
        final KeyPair keyPair_alice = kemHandler.generateNewKeypair();

        // encapsulation
        final SecretWithEncapsulation encResult = kemHandler.encapsulate(keyPair_alice.getPublic());
        final byte[] bob_shared = encResult.getSecret();
        final byte[] encapsulated = encResult.getEncapsulation();

        // decapsulation
        final byte[] alice_shared = kemHandler.decapsulate(encapsulated, keyPair_alice.getPrivate());
        assertTrue(Arrays.equals(bob_shared, alice_shared));
    }
}
