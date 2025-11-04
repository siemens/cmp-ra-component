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
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;

/**
 * base class for CMS data encryption
 */
public class CmsEncryptorBase {

    protected static Provider getProvider() {
        return CertUtility.getBouncyCastleProvider();
    }

    private final CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();
    private final CkgContext config;

    @SuppressWarnings("unused")
    private final String interfaceName;

    protected CmsEncryptorBase(final CkgContext config, String interfaceName) {
        this.config = config;
        this.interfaceName = interfaceName;
    }

    /**
     * encrypt the data
     *
     * @param msg data to encrypt
     * @return encrypted data
     * @throws CMSException             in case of an CMS processing error
     * @throws NoSuchAlgorithmException if getContentEncryptionAlg in config is
     *                                  unknown
     */
    public EnvelopedData encrypt(final byte[] msg) throws CMSException, NoSuchAlgorithmException {
        try {
            return encrypt(msg, CertUtility.getBouncyCastleProvider());
        } catch (CMSException | NoSuchAlgorithmException e) {
            throw e;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * encrypt the data
     *
     * @param msg data to encrypt
     * @return encrypted data
     * @throws CMSException             in case of an CMS processing error
     * @throws NoSuchAlgorithmException if getContentEncryptionAlg in config is
     *                                  unknown
     */
    private EnvelopedData encrypt(final byte[] msg, Provider provider) throws CMSException, NoSuchAlgorithmException {
        CMSProcessableByteArray content = new CMSProcessableByteArray(msg);
        final CMSEnvelopedData cmsEnvData = envGen.generate(
                content,
                new JceCMSContentEncryptorBuilder(AlgorithmHelper.getKeyEncryptionOID(config.getContentEncryptionAlg()))
                        .setProvider(provider)
                        .build());
        return EnvelopedData.getInstance(cmsEnvData.toASN1Structure().getContent());
    }

    /**
     * encrypt the data
     *
     * @param asn1Object ASN1.1 object to encrypt
     * @return encrypted data
     * @throws CMSException             in case of an CMS processing error
     * @throws IOException              in case of ASN.1 encoding error
     * @throws NoSuchAlgorithmException if getContentEncryptionAlg in config is
     *                                  unknown
     */
    public EnvelopedData encrypt(final ASN1Object asn1Object)
            throws CMSException, IOException, NoSuchAlgorithmException {
        return encrypt(asn1Object.getEncoded());
    }

    protected void addRecipientInfoGenerator(final RecipientInfoGenerator recipientGenerator) {
        envGen.addRecipientInfoGenerator(recipientGenerator);
    }
}
