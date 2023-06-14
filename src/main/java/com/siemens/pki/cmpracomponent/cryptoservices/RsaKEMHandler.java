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
package com.siemens.pki.cmpracomponent.cryptoservices;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMExtractor;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class RsaKEMHandler extends KemHandler {

    private final Digest hasher = new SHA256Digest();

    private final KDF2BytesGenerator kdf = new KDF2BytesGenerator(hasher);

    private static final int derivedKeyLength = 32;
    private static final int rsaKeyLength = 2048;
    private final RSAKEMGenerator encapsulator = new RSAKEMGenerator(derivedKeyLength, kdf, new SecureRandom());

    public RsaKEMHandler(String kemAlgorithm) throws NoSuchAlgorithmException {
        super(kemAlgorithm, KeyPairGeneratorFactory.getRsaKeyPairGenerator(rsaKeyLength));
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation, PrivateKey priv) {
        RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(
                true, ((RSAPrivateKey) priv).getModulus(), ((RSAPrivateKey) priv).getPrivateExponent());
        RSAKEMExtractor decapsulator = new RSAKEMExtractor(rsaKeyParameters, derivedKeyLength, kdf);
        return decapsulator.extractSecret(encapsulation);
    }

    @Override
    public SecretWithEncapsulation encapsulate(PublicKey pub) {
        final RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(
                false, ((RSAPublicKey) pub).getModulus(), ((RSAPublicKey) pub).getPublicExponent());
        return encapsulator.generateEncapsulated(rsaKeyParameters);
    }
}
