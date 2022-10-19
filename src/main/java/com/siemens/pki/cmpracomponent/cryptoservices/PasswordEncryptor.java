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

import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;

import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CkgPasswordContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpEnrollmentException;

/**
 * encryptor which uses the the MAC protected key management technique for
 * encryption
 *
 */
public class PasswordEncryptor extends CmsEncryptorBase {

    /**
     *
     * @param config
     *            specific configuration
     * @param initialRequestType
     * @param interfaceName
     * @throws NoSuchAlgorithmException
     *             if KEK in config is unknown
     * @throws CmpEnrollmentException
     *             if configuration is missing
     */
    public PasswordEncryptor(final CkgContext config,
            final int initialRequestType, final String interfaceName)
            throws NoSuchAlgorithmException, CmpEnrollmentException {
        super(config);
        final CkgPasswordContext passwordContext = config.getPasswordContext();
        if (passwordContext == null) {
            throw new CmpEnrollmentException(initialRequestType, interfaceName,
                    PKIFailureInfo.notAuthorized,
                    "support for key management technique Password-Based is not configured for central key generation");
        }
        final SharedSecretCredentialContext encryptionCredentials =
                passwordContext.getEncryptionCredentials();
        addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(
                AlgorithmHelper
                        .getKeyEncryptionOID(passwordContext.getKekAlg()),
                AlgorithmHelper.convertSharedSecretToPassword(
                        encryptionCredentials.getSharedSecret()))
                                .setProvider(
                                        CertUtility.getBouncyCastleProvider())
                                .setPasswordConversionScheme(
                                        PasswordRecipient.PKCS5_SCHEME2_UTF8)
                                .setPRF(AlgorithmHelper
                                        .getPrf(encryptionCredentials.getPrf()))
                                .setSaltAndIterationCount(
                                        encryptionCredentials.getSalt(),
                                        encryptionCredentials
                                                .getIterationCount()));
    }
}
