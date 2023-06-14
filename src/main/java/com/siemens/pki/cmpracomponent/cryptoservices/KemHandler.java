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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public abstract class KemHandler {

    protected static final SecureRandom RANDOMGENERATOR = new SecureRandom();

    protected static final String SYMMETRIC_CIPHER = "AES";

    protected static final Provider BC_PQ_PROV = new BouncyCastlePQCProvider();

    static {
        Security.addProvider(BC_PQ_PROV);
        Security.addProvider(CertUtility.getBouncyCastleProvider());
    }

    public static KemHandler createKemHandler(String kemAlgorithm) throws NoSuchAlgorithmException {
        if (ISOIECObjectIdentifiers.id_kem_rsa.getId().equalsIgnoreCase(kemAlgorithm)
                || "RSA".equalsIgnoreCase(kemAlgorithm)) {
            return new RsaKEMHandler(kemAlgorithm);
        }
        return new PqKemHandler(kemAlgorithm);
    }

    protected final String kemAlgorithm;

    private final KeyPairGenerator kpg;

    public KemHandler(String kemAlgorithm, KeyPairGenerator kpg) {
        super();
        this.kemAlgorithm = kemAlgorithm;
        this.kpg = kpg;
    }

    /**
     * KEM decapsulation
     *
     * @param encapsulation cipher text
     * @param priv          private part of KEM keypair
     * @return shared secret
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     */
    public abstract byte[] decapsulate(byte[] encapsulation, PrivateKey priv)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException;

    /**
     * KEM encapsulation
     *
     * @param pub public part of KEM keypair
     * @return shared secret and cipher text
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public abstract SecretWithEncapsulation encapsulate(PublicKey pub)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * generate new KEM keypair
     *
     * @return new KEM keypair
     */
    public KeyPair generateNewKeypair() {
        return kpg.generateKeyPair();
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() throws NoSuchAlgorithmException {
        return AlgorithmHelper.getKemAlgIdFromName(kemAlgorithm);
    }
}
