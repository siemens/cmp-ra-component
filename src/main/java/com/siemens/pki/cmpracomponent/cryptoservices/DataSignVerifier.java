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

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.BiPredicate;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a verifier for CMS signed data
 */
public class DataSignVerifier extends TrustCredentialAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(DataSignVerifier.class);
    private static final JcaSimpleSignerInfoVerifierBuilder builder =
            new JcaSimpleSignerInfoVerifierBuilder().setProvider(CertUtility.getBouncyCastleProvider());

    /**
     * verify and strip off a signature
     * @param encodedSignedData date to verify
     * @return date without signature
     * @throws CertificateException in case of error
     * @throws CMSException in case of error
     * @throws IOException in case of error
     */
    public static byte[] verifySignature(final byte[] encodedSignedData)
            throws CertificateException, CMSException, IOException {
        return verifySignature(encodedSignedData, (cert, additionalCerts) -> true);
    }

    private static byte[] verifySignature(
            final byte[] encodedSignedData,
            final BiPredicate<X509CertificateHolder, List<X509Certificate>> trustValidator)
            throws CMSException, IOException, CertificateException {

        final CMSSignedData signedData = new CMSSignedData(
                new ContentInfo(CMSObjectIdentifiers.signedData, SignedData.getInstance(encodedSignedData)));
        final SignerInformationStore signers = signedData.getSignerInfos();
        final Store<X509CertificateHolder> certs = signedData.getCertificates();
        final List<X509Certificate> allCerts = new ArrayList<>();
        for (final X509CertificateHolder aktCert : certs.getMatches(null)) {
            allCerts.add(CertUtility.asX509Certificate(aktCert.getEncoded()));
        }
        for (final SignerInformation signerInfo : signers) {
            @SuppressWarnings("unchecked")
            final Collection<X509CertificateHolder> certCollection = certs.getMatches(signerInfo.getSID());
            final X509CertificateHolder cert = certCollection.iterator().next();
            try {
                if (signerInfo.verify(builder.build(cert)) && trustValidator.test(cert, allCerts)) {
                    final CMSTypedData cmsData = signedData.getSignedContent();
                    final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    cmsData.write(bOut);
                    return bOut.toByteArray();
                }
            } catch (final Exception e) {
                // try next signer
            }
        }
        return null;
    }

    /**
     * ctor
     * @param config context used for verification
     * @param interfaceName CMP interface name for logging
     */
    public DataSignVerifier(final VerificationContext config, String interfaceName) {
        super(config, interfaceName);
    }

    private boolean validate(final X509CertificateHolder cert, final List<X509Certificate> allCerts)
            throws CertificateException, IOException, NoSuchProviderException {
        return validateCertAgainstTrust(CertUtility.asX509Certificate(cert.getEncoded()), allCerts) != null;
    }

    /**
     * Verify the passed in encoding of a CMS SignedData, assumes encapsulated data.
     *
     * @param encodedSignedData the BER encoding of the SignedData
     * @return signed content or null if not trusted
     * @throws IOException          in case of ASN.1 encoding error
     * @throws CMSException         in case of error in CMS processing
     * @throws CertificateException in case of error in certificate processing
     */
    public byte[] verifySignatureAndTrust(final byte[] encodedSignedData)
            throws IOException, CertificateException, CMSException {
        return verifySignature(encodedSignedData, (cert, additionalIntermediateCerts) -> {
            try {
                return validate(cert, additionalIntermediateCerts);
            } catch (final Exception e) {
                return false;
            }
        });
    }

    /**
     * strip off a private key from signed date
     * @param encodedSignedData the BER encoding of the SignedData
     * @return found private key
     * @throws CertificateException in case of error
     * @throws IOException in case of error
     * @throws CMSException in case of error
     */
    public PrivateKey verifySignedKey(final byte[] encodedSignedData)
            throws CertificateException, IOException, CMSException {
        final byte[] verifiedContent = verifySignatureAndTrust(encodedSignedData);
        if (verifiedContent == null) {
            return null;
        }
        final PKCS8EncodedKeySpec pkcs8EncKeySpec = new PKCS8EncodedKeySpec(verifiedContent);
        for (final String keyType : new String[] {"RSA", "EC", "Ed448", "Ed25519"}) {
            try {
                final KeyFactory factory = KeyFactory.getInstance(keyType, CertUtility.getBouncyCastleProvider());
                return factory.generatePrivate(pkcs8EncKeySpec);
            } catch (final Exception e) {
                // try next key type
            }
        }
        LOGGER.error("could not load private key");
        return null;
    }
}
