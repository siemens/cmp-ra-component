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
import com.siemens.pki.cmpracomponent.configuration.CkgKeyAgreementContext;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpEnrollmentException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;

/**
 * encryptor which uses the key agreement key management technique for
 * encryption
 */
public class KeyAgreementEncryptor extends CmsEncryptorBase {

    /**
     * ctor
     * @param config             specific configuration
     * @param protectingCert     the public key certificate for the targeted
     *                           recipients.
     * @param interfaceName      CMP interface name for logging
     * @param initialRequestType type of initial request (cr, ir, kur)
     * @throws CmpEnrollmentException   if configuration is missing
     * @throws NoSuchAlgorithmException if some predefined algorithms are not
     *                                  supported
     */
    public KeyAgreementEncryptor(
            final CkgContext config,
            final X509Certificate protectingCert,
            final int initialRequestType,
            final String interfaceName)
            throws GeneralSecurityException, CmpEnrollmentException {
        super(config);
        final CkgKeyAgreementContext keyAgreementContext = config.getKeyAgreementContext();
        if (keyAgreementContext == null) {
            throw new CmpEnrollmentException(
                    initialRequestType,
                    interfaceName,
                    PKIFailureInfo.notAuthorized,
                    "support for key management technique Key Agreement is not configured for central key generation");
        }
        final JceKeyAgreeRecipientInfoGenerator infGen = new JceKeyAgreeRecipientInfoGenerator(
                AlgorithmHelper.getKeyAgreementOID(keyAgreementContext.getKeyAgreementAlg()),
                keyAgreementContext.getOwnPrivateKey(),
                keyAgreementContext.getOwnPublicKey(),
                AlgorithmHelper.getKekOID(keyAgreementContext.getKeyEncryptionAlg()));

        infGen.addRecipient(keyAgreementContext.getRecipient(protectingCert));
        addRecipientInfoGenerator(infGen.setProvider(CertUtility.getBouncyCastleProvider()));
    }
}
