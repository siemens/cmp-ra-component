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
package com.siemens.pki.cmpracomponent.test.framework;

import com.siemens.pki.cmpracomponent.cryptoservices.KeyPairGeneratorFactory;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

/**
 * provide lists of algoritrhms to test
 */
public class TcAlgs {
    // utility class
    private TcAlgs() {}

    public static List<Object[]> getPqSignatureAlgorithms() throws GeneralSecurityException {
        return Arrays.asList(new Object[][] {
            {"id_ml_dsa_44", KeyPairGeneratorFactory.getGenericKeyPairGenerator(NISTObjectIdentifiers.id_ml_dsa_44)},
            {"id_ml_dsa_65", KeyPairGeneratorFactory.getGenericKeyPairGenerator(NISTObjectIdentifiers.id_ml_dsa_65)},
            {"id_ml_dsa_87", KeyPairGeneratorFactory.getGenericKeyPairGenerator(NISTObjectIdentifiers.id_ml_dsa_87)},
            {
                "id_slh_dsa_sha2_128s",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(NISTObjectIdentifiers.id_slh_dsa_sha2_128s)
            },
            //
        });
    }

    public static List<Object[]> getCompositeAlgorithms() throws GeneralSecurityException {
        return Arrays.asList(new Object[][] {
            {
                "MLDSA44-RSA2048-PSS-SHA256",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256)
            },
            {
                "MLDSA44-RSA2048-PKCS15-SHA256",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(
                        MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256)
            },
            {
                "MLDSA44-ECDSA-P256-SHA256",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            },
            {
                "MLDSA44-ECDSA-BRAINPOOLP256R1-SHA256",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(
                        MiscObjectIdentifiers.id_MLDSA44_ECDSA_brainpoolP256r1_SHA256)
            },
            {
                "MLDSA44-ED25519-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512)
            },
            {
                "MLDSA65-RSA3072-PSS-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512)
            },
            {
                "MLDSA65-RSA3072-PKCS15-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(
                        MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512)
            },
            {
                "MLDSA65-ECDSA-BRAINPOOLP256R1-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(
                        MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512)
            },
            {
                "MLDSA65-ECDSA-P256-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512)
            },
            {
                "MLDSA65-ED25519-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512)
            },
            {
                "MLDSA87-ECDSA-P384-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512)
            },
            {
                "MLDSA87-ECDSA-BRAINPOOLP384R1-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(
                        MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512)
            },
            {
                "MLDSA87-ED448-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512)
            },
            {
                "FALCON512-ECDSA-P256-SHA256",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_Falcon512_ECDSA_P256_SHA256)
            },
            {
                "FALCON512-ECDSA-BRAINPOOLP256R1-SHA256",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(
                        MiscObjectIdentifiers.id_Falcon512_ECDSA_brainpoolP256r1_SHA256)
            },
            {
                "FALCON512-ED25519-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_Falcon512_Ed25519_SHA512)
            },
            //
        });
    }

    public static List<Object[]> getKemAlgorithms() throws GeneralSecurityException {
        return Arrays.asList(new Object[][] {
            {
                "id_alg_ml_kem_512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(NISTObjectIdentifiers.id_alg_ml_kem_512)
            },
            {
                "id_alg_ml_kem_1024",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(NISTObjectIdentifiers.id_alg_ml_kem_1024)
            },
        });
    }

    public static List<Object[]> getClassicSignatureAlgorithms() throws GeneralSecurityException {
        return Arrays.asList(new Object[][] {
            {"RSA1024", KeyPairGeneratorFactory.getRsaKeyPairGenerator(1024)},
            {"RSA2048", KeyPairGeneratorFactory.getRsaKeyPairGenerator(2048)},
            {"Ed448", KeyPairGeneratorFactory.getEdDsaKeyPairGenerator("Ed448")},
            {"Ed25519", KeyPairGeneratorFactory.getEdDsaKeyPairGenerator("Ed25519")},
            {"secp256r1", KeyPairGeneratorFactory.getEcKeyPairGenerator("secp256r1")},
            //
        });
    }
}
