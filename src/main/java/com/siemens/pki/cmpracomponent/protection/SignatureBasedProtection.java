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

import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.BaseCredentialService;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * a {@link ProtectionProvider} enforcing a CMP message with signature based
 * protection
 */
public class SignatureBasedProtection extends BaseCredentialService implements ProtectionProvider {

    /**
     * ctor
     * @param config specific configuration
     * @param interfaceName CMP interface name for logging
     */
    public SignatureBasedProtection(final SignatureCredentialContext config, String interfaceName) {
        super(config, interfaceName);
    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() throws CertificateException {
        final List<X509Certificate> certChain = getCertChain();
        if (certChain.size() <= 1) {
            // protecting cert might be selfsigned
            Arrays.asList(CertUtility.asCmpCertificates(certChain));
        }
        // filter out selfsigned certificates
        return certChain.stream()
                .filter(CertUtility::isIntermediateCertificate)
                .map(t -> {
                    try {
                        return CertUtility.asCmpCertificate(t);
                    } catch (final CertificateException e) {
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toList());
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() {
        return getSignatureAlgorithm();
    }

    @Override
    public DERBitString getProtectionFor(final ProtectedPart protectedPart)
            throws GeneralSecurityException, IOException {
        final Signature sig = Signature.getInstance(getSignatureAlgorithmName());
        sig.initSign(getPrivateKey());
        sig.update(protectedPart.getEncoded(ASN1Encoding.DER));
        return new DERBitString(sig.sign());
    }

    @Override
    public GeneralName getSender() {
        return new GeneralName(X500Name.getInstance(
                getEndCertificate().getSubjectX500Principal().getEncoded()));
    }

    @Override
    public DEROctetString getSenderKID() {
        return CertUtility.extractSubjectKeyIdentifierFromCert(getEndCertificate());
    }
}
