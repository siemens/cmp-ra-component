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
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

/**
 * provide lists of algoritrhms to test
 */
public class TcAlgs {
    // utility class
    private TcAlgs() {}

    public static List<Object[]> getPqSignatureAlgorithms() throws GeneralSecurityException {
        List<Object[]> ret = new ArrayList<>();
        for (int i = 17; i <= 31; i++) {
            ASN1ObjectIdentifier oid = NISTObjectIdentifiers.sigAlgs.branch("" + i);
            ret.add(new Object[] {
                MessageDumper.getOidDescriptionForOid(oid).getId(),
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(oid)
            });
        }
        // takes very long
        //    	for (int i=35;i<=46;i++) {
        // short version
        for (int i : Arrays.asList(35, 46)) {
            ASN1ObjectIdentifier oid = NISTObjectIdentifiers.sigAlgs.branch("" + i);
            ret.add(new Object[] {
                MessageDumper.getOidDescriptionForOid(oid).getId(),
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(oid)
            });
        }
        return ret;
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
                "MLDSA44-ED25519-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512)
            },
            {
                "MLDSA65-ED25519-SHA512",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512)
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
                "id_alg_ml_kem_768",
                KeyPairGeneratorFactory.getGenericKeyPairGenerator(NISTObjectIdentifiers.id_alg_ml_kem_768)
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
