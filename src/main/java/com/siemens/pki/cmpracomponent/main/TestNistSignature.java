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
package com.siemens.pki.cmpracomponent.main;

import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestNistSignature {

    private static final BouncyCastleProvider bcprov = new BouncyCastleProvider();

    private static Signature deriveSignatureFromKey(Key key) throws Exception {
        return Signature.getInstance(key.getAlgorithm(), bcprov);
    }

    public static void main(String[] args) {
        try {
            // works
            KeyPairGenerator ml_dsa_kp =
                    KeyPairGenerator.getInstance(NISTObjectIdentifiers.id_ml_dsa_87.getId(), bcprov);
            Signature ml_dsa_sig =
                    deriveSignatureFromKey(ml_dsa_kp.generateKeyPair().getPrivate());
            System.out.println("got sig for " + ml_dsa_sig.getAlgorithm());

            // fails
            KeyPairGenerator slh_dsa_kp =
                    KeyPairGenerator.getInstance(NISTObjectIdentifiers.id_slh_dsa_sha2_128s.getId(), bcprov);
            Signature slh_dsa_sig =
                    deriveSignatureFromKey(slh_dsa_kp.generateKeyPair().getPrivate());
            System.out.println("got sig for " + slh_dsa_sig.getAlgorithm());

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
