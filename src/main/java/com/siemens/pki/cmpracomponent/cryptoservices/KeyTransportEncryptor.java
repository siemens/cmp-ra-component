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

import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CkgKeyTransportContext;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpEnrollmentException;
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

/**
 * encryptor which uses the key transport key management technique for
 * encryption
 */
public class KeyTransportEncryptor extends CmsEncryptorBase {
    /**
     * ctor
     * @param config             specific configuration
     * @param protectingCert     the public key certificate for the targeted
     *                           recipients.
     * @param interfaceName      CMP interface name for logging
     * @param initialRequestType type of initial request (cr, ir, kur)
     * @throws NoSuchAlgorithmException if some predefined algorithms are not
     *                                  supported
     * @throws CmpEnrollmentException   if configuration is missing
     */
    public KeyTransportEncryptor(
            final CkgContext config,
            final X509Certificate protectingCert,
            final int initialRequestType,
            final String interfaceName)
            throws NoSuchAlgorithmException, CmpEnrollmentException {
        super(config, interfaceName);
        final CkgKeyTransportContext transportContext =
                ConfigLogger.log(interfaceName, "CkgContext.getKeyTransportContext()", config::getKeyTransportContext);
        if (transportContext == null) {
            throw new CmpEnrollmentException(
                    initialRequestType,
                    interfaceName,
                    PKIFailureInfo.notAuthorized,
                    "support for key management technique Key Transport is not configured for central key generation");
        }
        final JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
        final X509Certificate encryptionCert = ConfigLogger.log(
                interfaceName,
                "CkgKeyTransportContext.getRecipient(X509Certificate)",
                () -> transportContext.getRecipient(protectingCert));
        final PublicKey publicKey = encryptionCert.getPublicKey();
        addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
                        jcaX509ExtensionUtils
                                .createSubjectKeyIdentifier(publicKey)
                                .getKeyIdentifier(),
                        publicKey)
                .setProvider(getProvider()));
    }
}
