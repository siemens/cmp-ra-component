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
package com.siemens.pki.cmpracomponent.protection;

import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMac;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMacFactory;
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * a {@link ProtectionProvider} enforcing a CMP message with PBMAC1 protection
 */
public class PBMAC1Protection extends MacProtection {

    /**
     * ctor
     * @param config specific configuration
     * @param interfaceName CMP interface name for logging
     * @throws InvalidKeySpecException  in case of internal error
     * @throws NoSuchAlgorithmException in case of unsupported algorithm
     * @throws InvalidKeyException      in case of internal error
     */
    public PBMAC1Protection(final SharedSecretCredentialContext config, String interfaceName)
            throws InvalidKeySpecException, InvalidKeyException, NoSuchAlgorithmException {
        super(config, interfaceName);
        final byte[] salt =
                ConfigLogger.log(interfaceName, "SharedSecretCredentialContext.getSalt()", () -> config.getSalt());
        final AlgorithmIdentifier prfAlgorithm = AlgorithmHelper.getPrf(ConfigLogger.log(
                        interfaceName, "SharedSecretCredentialContext.getPrf()", () -> config.getPrf()))
                .getAlgorithmID();
        final int keyLength = ConfigLogger.log(
                interfaceName, "SharedSecretCredentialContext.getkeyLength()", () -> config.getkeyLength());
        final AlgorithmIdentifier keyDerivationFunc = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(
                        salt,
                        ConfigLogger.log(
                                interfaceName,
                                "SharedSecretCredentialContext.getIterationCount()",
                                () -> config.getIterationCount()),
                        keyLength,
                        prfAlgorithm));
        final SecretKeyFactory keyFact =
                AlgorithmHelper.getSecretKeyFactory(prfAlgorithm.getAlgorithm().getId());
        final SecretKey key = keyFact.generateSecret(new PBEKeySpec(
                AlgorithmHelper.convertSharedSecretToPassword(config.getSharedSecret()),
                salt,
                config.getIterationCount(),
                keyLength));
        final AlgorithmIdentifier messageAuthScheme =
                new AlgorithmIdentifier(AlgorithmHelper.getOidForMac(ConfigLogger.log(
                        interfaceName,
                        "SharedSecretCredentialContext.getMacAlgorithm()",
                        () -> config.getMacAlgorithm())));
        final AlgorithmIdentifier protectionAlg = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_PBMAC1, new PBMAC1Params(keyDerivationFunc, messageAuthScheme));
        final WrappedMac wrappedMac = WrappedMacFactory.createWrappedMac(messageAuthScheme, key.getEncoded());
        init(protectionAlg, wrappedMac);
    }
}
