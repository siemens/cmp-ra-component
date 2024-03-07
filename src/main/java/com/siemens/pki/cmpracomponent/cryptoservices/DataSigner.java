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

import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;

/**
 * a signer to produce CMS SignedData
 */
public class DataSigner {

    private final ASN1ObjectIdentifier id_ct_KP_aKeyPackage = new ASN1ObjectIdentifier("1.2.16.840.1.101.2.1.2.78.5");

    private final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

    /**
     * ctor
     * @param credentialService credentials used for signing
     * @throws OperatorCreationException in case of error
     * @throws CertificateEncodingException in case of error
     * @throws IOException in case of error
     * @throws CMSException in case of error
     */
    public DataSigner(final BaseCredentialService credentialService)
            throws OperatorCreationException, CertificateEncodingException, IOException, CMSException {
        final SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider(CertUtility.getBouncyCastleProvider())
                .build(
                        credentialService.getSignatureAlgorithmName(),
                        credentialService.getPrivateKey(),
                        credentialService.getEndCertificate());
        gen.addSignerInfoGenerator(signerInfoGenerator);

        final List<X509CertificateHolder> certChain = new ArrayList<>();
        final List<X509Certificate> baseCredentialCertChain = credentialService.getCertChain();
        for (final X509Certificate aktCert : baseCredentialCertChain) {
            if (baseCredentialCertChain.size() == 1 || CertUtility.isIntermediateCertificate(aktCert)) {
                certChain.add(new X509CertificateHolder(aktCert.getEncoded()));
            }
        }
        gen.addCertificates(new CollectionStore<>(certChain));
    }

    /**
     * ctor
     * @param privateKey private key used for signing
     * @param endCertificate certificate used for signing
     * @param interfaceName CMP interface name for logging
     * @throws CertificateEncodingException in case of error
     * @throws OperatorCreationException in case of error
     * @throws IOException in case of error
     * @throws CMSException in case of error
     */
    public DataSigner(final PrivateKey privateKey, final X509Certificate endCertificate, String interfaceName)
            throws CertificateEncodingException, OperatorCreationException, IOException, CMSException {
        this(new BaseCredentialService(
                new SignatureCredentialContext() {

                    @Override
                    public List<X509Certificate> getCertificateChain() {
                        return Collections.singletonList(endCertificate);
                    }

                    @Override
                    public PrivateKey getPrivateKey() {
                        return privateKey;
                    }
                },
                interfaceName));
    }

    /**
     * Create a SignedData structure
     *
     * @param msg the raw message data to encapsulate and sign
     * @return the SignedData.
     * @throws CMSException in case of error
     */
    public SignedData signData(final byte[] msg) throws CMSException {
        final CMSSignedData cmsSigned = gen.generate(new CMSProcessableByteArray(id_ct_KP_aKeyPackage, msg), true);
        final ContentInfo contentInfo = cmsSigned.toASN1Structure();
        return SignedData.getInstance(contentInfo.getContent());
    }

    /**
     * Create a SignedData structure
     *
     * @param privateKey a private key to encapsulate and sign
     * @return the SignedData
     * @throws CMSException in case of an CMS processing error
     * @throws IOException  in case of ASN.1 encoding error
     */
    public SignedData signPrivateKey(final PrivateKey privateKey) throws CMSException, IOException {
        return signData(PrivateKeyInfo.getInstance(privateKey.getEncoded()).getEncoded(ASN1Encoding.DER));
    }
}
