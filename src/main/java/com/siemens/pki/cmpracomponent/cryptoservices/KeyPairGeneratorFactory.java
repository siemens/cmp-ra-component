/*
 *  Copyright (c) 2022 Siemens AG
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

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * helper class for generation of {@link KeyPairGenerator}s
 */
public class KeyPairGeneratorFactory {
    private static final SecureRandom RANDOM = new SecureRandom();

    private KeyPairGeneratorFactory() {}

    /**
     * Generate ECDSA key pair generator for the requested curve.
     *
     * @param curve the name of the EC curve requested
     * @return the generated key pair generator
     * @throws GeneralSecurityException if key pair generator generation failed
     */
    public static KeyPairGenerator getEcKeyPairGenerator(final String curve) throws GeneralSecurityException {

        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", CertUtility.getBouncyCastleProvider());
        try {
            final ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve);
            keyGen.initialize(ecSpec, RANDOM);
        } catch (final IllegalArgumentException exception) {
            // we try to get the EC parameters by name
            final X9ECParameters ecP = CustomNamedCurves.getByName(curve);
            final ECParameterSpec ecSpec =
                    new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
            keyGen.initialize(ecSpec, RANDOM);
        }
        return keyGen;
    }

    /**
     * Generate EdDSA key pair generator for the requested curve.
     *
     * @param keyType type of EdDSA key, "Ed25519" or "Ed448"
     * @return the generated key pair generator
     * @throws GeneralSecurityException if key pair generator generation failed
     */
    public static KeyPairGenerator getEdDsaKeyPairGenerator(final String keyType) throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(keyType, CertUtility.getBouncyCastleProvider());
    }

    /**
     * Generate key pair generator, let BC find the Algorithm.
     *
     * @param algOid Algorithm OID
     * @return the generated key pair generator
     * @throws GeneralSecurityException if key pair generator generation failed
     */
    public static KeyPairGenerator getGenericKeyPairGenerator(final ASN1ObjectIdentifier algOid)
            throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(algOid.getId(), CertUtility.getBouncyCastleProvider());
    }

    /**
     * Generate key pair generator, let BC find the Algorithm.
     *
     * @param keyType type of key
     * @return the generated key pair generator
     * @throws GeneralSecurityException if key pair generator generation failed
     */
    public static KeyPairGenerator getGenericKeyPairGenerator(final String keyType) throws GeneralSecurityException {
        return KeyPairGenerator.getInstance(keyType, CertUtility.getBouncyCastleProvider());
    }

    /**
     * generate RSA key pair generator
     *
     * @param keyLength length of generated keys
     * @return generated KeyPairGenerator
     * @throws NoSuchAlgorithmException if RSA is not supported
     */
    public static KeyPairGenerator getRsaKeyPairGenerator(final int keyLength) throws NoSuchAlgorithmException {
        final KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(keyLength);
        return keygen;
    }
}
