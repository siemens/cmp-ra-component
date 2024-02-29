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

import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * a factory for {@link ProtectionProvider}
 */
public class ProtectionProviderFactory {

    /**
     * create a {@link ProtectionProvider} according to the given configuration
     *
     * @param config specific configuration
     * @param interfaceName CMP interface name for logging
     * @return a new {@link ProtectionProvider}
     * @throws NoSuchAlgorithmException in case of unknown algorithm
     * @throws InvalidKeyException      in case of internal error
     * @throws InvalidKeySpecException  in case of internal error
     */
    public static ProtectionProvider createProtectionProvider(final CredentialContext config, String interfaceName)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (config instanceof SharedSecretCredentialContext) {
            final SharedSecretCredentialContext ssConfig = (SharedSecretCredentialContext) config;
            final String passwordBasedMacAlgorithm = ConfigLogger.log(
                    interfaceName,
                    "SharedSecretCredentialContext.getPasswordBasedMacAlgorithm()",
                    ssConfig::getPasswordBasedMacAlgorithm);
            switch (passwordBasedMacAlgorithm.toLowerCase()) {
                case "1.2.840.113533.7.66.13":
                case "id-passwordbasedmac":
                case "passwordbasedmac":
                case "pbm":
                    return new PasswordBasedMacProtection(ssConfig, interfaceName);
                case "1.2.840.113549.1.5.14":
                case "id-pbmac1":
                case "pbmac1":
                    return new PBMAC1Protection(ssConfig, interfaceName);
                default:
                    throw new NoSuchAlgorithmException(passwordBasedMacAlgorithm);
            }
        }
        if (config instanceof SignatureCredentialContext) {
            return new SignatureBasedProtection((SignatureCredentialContext) config, interfaceName);
        }
        return ProtectionProvider.NO_PROTECTION;
    }

    // utility class
    private ProtectionProviderFactory() {}
}
