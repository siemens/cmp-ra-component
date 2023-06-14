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

import com.siemens.pki.cmpracomponent.cryptoservices.KdfFunction;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class TestHKDF {

    @Test
    public void testDeriveKey() {
        final String saltStr = "\u00e0Q\u0010o!'Dw75G\u0095{\u00fd\u00ccB";
        final byte[] salt = saltStr.getBytes(StandardCharsets.ISO_8859_1);
        final KdfFunction kdf = KdfFunction.getKdfInstance(
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.28")));
        final SecretKey ret = kdf.deriveKey("input key".getBytes(), 32, salt, "dummy context".getBytes());
        final String okmHex = Hex.toHexString(ret.getEncoded());

        Assert.assertEquals(okmHex, "4ea3a995c5d5953043680aa729818fad89ec1645f158cd5b2905ff8001373ea2");
    }

    @Test
    public void testHKDF() {
        final byte[] ikm = "input key".getBytes();
        // byte[] salt = "salt".getBytes();
        final String saltStr = "\u00e0Q\u0010o!'Dw75G\u0095{\u00fd\u00ccB";
        final byte[] salt = saltStr.getBytes(StandardCharsets.ISO_8859_1);
        final byte[] info = "dummy context".getBytes();
        final int length = 32;

        final HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info));

        final byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);

        final String okmHex = Hex.toHexString(okm);

        Assert.assertEquals(okmHex, "4ea3a995c5d5953043680aa729818fad89ec1645f158cd5b2905ff8001373ea2");
    }
}
