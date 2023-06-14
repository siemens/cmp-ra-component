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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class KdfFunction {
    // We assume that only HKDF is used, because it is the only one that fits the
    // proposed structure in RFC4210bis,
    // expecting contextInfo and allowing no salt. Thus, when it comes to
    // customizable parameters, the only one that
    // varies is the hashing algorithm.

    public static KdfFunction getKdfInstance(AlgorithmIdentifier keyDerivationFunc) {
        // The source of OID definitions:
        // https://datatracker.ietf.org/doc/html/rfc8619#section-2
        // id-alg-hkdf-with-sha256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        // us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 28 }
        //
        // id-alg-hkdf-with-sha384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        // us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 29 }
        //
        // id-alg-hkdf-with-sha512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        // us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 30 }

        final ASN1ObjectIdentifier algorithm = keyDerivationFunc.getAlgorithm();
        if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha256.equals(algorithm)) {
            return new KdfFunction(new SHA256Digest());
        }
        if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha384.equals(algorithm)) {
            return new KdfFunction(new SHA384Digest());
        }
        if (PKCSObjectIdentifiers.id_alg_hkdf_with_sha512.equals(algorithm)) {
            return new KdfFunction(new SHA512Digest());
        }
        throw new UnsupportedOperationException();
    }

    // If we'll use other KDFs later, more parameters might be needed besides
    // `digest`.
    private final Digest digest;

    public KdfFunction(Digest digest) {
        this.digest = digest;
    }

    /**
     * @param sharedSecret the input key material to derive a key from
     * @param keyLength    how long should the generated key be, in bytes
     * @param salt         optional, random salt to use during key derivation; set
     *                     to null if unused
     * @param context      optional, raw bytes to be treated as the context of the
     *                     key derivation process, set to <code>null</code> if unused
     * @return derived key, also known as "output key material" in HKDF terminology
     */
    public SecretKey deriveKey(byte[] sharedSecret, int keyLength, byte[] salt, byte[] context) {
        final HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
        hkdf.init(new HKDFParameters(sharedSecret, salt, context));

        final byte[] derivedKey = new byte[keyLength];
        hkdf.generateBytes(derivedKey, 0, keyLength);

        return new SecretKeySpec(derivedKey, "HKDF");
    }
}
