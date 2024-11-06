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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipientId;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;

/**
 * CMS data decryption
 */
public class CmsDecryptor {

    private static final RecipientId passRecipientId = new PasswordRecipientId();

    private final JceKeyTransRecipientId transRecipientId;

    private final RecipientId agreeRecipientId;

    private PrivateKey recipientKey;

    private char[] passwd;

    /**
     * ctor
     *
     * @param recipientCert cert used to decrypt
     * @param recipientKey  private key used to decrypt
     * @param passwd        password used to decrypt
     */
    public CmsDecryptor(final X509Certificate recipientCert, final PrivateKey recipientKey, final char[] passwd) {
        this.recipientKey = recipientKey;
        this.passwd = passwd;

        if (recipientCert != null && recipientKey != null) {
            transRecipientId = new JceKeyTransRecipientId(recipientCert);
            agreeRecipientId = new JceKeyAgreeRecipientId(recipientCert);
        } else {
            transRecipientId = null;
            agreeRecipientId = null;
        }
    }

    /**
     * Extract the original data that was encrypted from the EnvelopedData structure
     * by using the recipient matching the passed in parameters.
     *
     * @param envelopedData the EnvelopedData structure.
     * @return the original data that was enveloped as a byte[].
     * @throws CMSException in case of an CMS processing error
     */
    public byte[] decrypt(final EnvelopedData envelopedData) throws CMSException {

        final CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(
                new ContentInfo(envelopedData.getEncryptedContentInfo().getContentType(), envelopedData));

        final RecipientInformationStore recipients = cmsEnvelopedData.getRecipientInfos();

        if (agreeRecipientId != null) {
            RecipientInformation recipient = recipients.get(agreeRecipientId);
            if (recipient != null) {
                return recipient.getContent(new JceKeyAgreeEnvelopedRecipient(recipientKey)
                        .setProvider(CertUtility.getBouncyCastleProvider()));
            }
        }
        if (transRecipientId != null) {
            RecipientInformation recipient = recipients.get(transRecipientId);
            if (recipient != null) {
                return recipient.getContent(new JceKeyTransEnvelopedRecipient(recipientKey)
                        .setProvider(CertUtility.getBouncyCastleProvider()));
            }
        }
        RecipientInformation recipient = recipients.get(passRecipientId);
        if (recipient != null) {
            return recipient.getContent(new JcePasswordEnvelopedRecipient(passwd)
                    .setProvider(CertUtility.getBouncyCastleProvider())
                    .setPasswordConversionScheme(PasswordRecipient.PKCS5_SCHEME2_UTF8));
        }
        throw new IllegalArgumentException("recipient for certificate not found");
    }
}
