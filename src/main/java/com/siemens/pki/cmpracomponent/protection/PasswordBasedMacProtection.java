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
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * a {@link ProtectionProvider} enforcing a CMP message with password based MAC
 * protection
 */
public class PasswordBasedMacProtection extends MacProtection {
    /**
     * ctor
     * @param config specific configuration
     * @throws InvalidKeyException      in case of internal error
     * @throws NoSuchAlgorithmException in case of unsupported algorithm
     */
    public PasswordBasedMacProtection(final SharedSecretCredentialContext config)
            throws InvalidKeyException, NoSuchAlgorithmException {
        super(config);

        final byte[] raSecret = config.getSharedSecret();

        final byte[] protectionSalt = config.getSalt();
        byte[] calculatingBaseKey = new byte[raSecret.length + protectionSalt.length];
        System.arraycopy(raSecret, 0, calculatingBaseKey, 0, raSecret.length);
        System.arraycopy(protectionSalt, 0, calculatingBaseKey, raSecret.length, protectionSalt.length);
        // Construct the base key according to rfc4210, section 5.1.3.1
        final MessageDigest dig = AlgorithmHelper.getMessageDigest(config.getPrf());
        final int iterationCount = config.getIterationCount();
        for (int i = 0; i < iterationCount; i++) {
            calculatingBaseKey = dig.digest(calculatingBaseKey);
            dig.reset();
        }
        final AlgorithmIdentifier macAlgorithm =
                new AlgorithmIdentifier(AlgorithmHelper.getOidForMac(config.getMacAlgorithm()));
        final Mac protectingMac =
                AlgorithmHelper.getMac(macAlgorithm.getAlgorithm().getId());
        protectingMac.init(new SecretKeySpec(calculatingBaseKey, protectingMac.getAlgorithm()));
        final WrappedMac wrappedMac = in -> {
            protectingMac.update(in);
            final byte[] ret = protectingMac.doFinal();
            protectingMac.reset();
            return ret;
        };
        final AlgorithmIdentifier protectionAlg = new AlgorithmIdentifier(
                CMPObjectIdentifiers.passwordBasedMac,
                new PBMParameter(
                        protectionSalt,
                        AlgorithmHelper.findDigestAlgoritm(dig),
                        iterationCount,
                        new AlgorithmIdentifier(AlgorithmHelper.getOidForMac(protectingMac.getAlgorithm()))));
        init(protectionAlg, wrappedMac);
    }
}
