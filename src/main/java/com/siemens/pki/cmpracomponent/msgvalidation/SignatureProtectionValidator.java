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
package com.siemens.pki.cmpracomponent.msgvalidation;

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.cryptoservices.TrustCredentialAdapter;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class validates the signature based protection of all incoming messages
 * and generates proper error responses on failed validation.
 */
class SignatureProtectionValidator implements ValidatorIF<Void> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureProtectionValidator.class);

    private final String interfaceName;

    private final VerificationContext config;

    public SignatureProtectionValidator(final String interfaceName, final VerificationContext config) {
        this.config = config;
        this.interfaceName = interfaceName;
    }

    private void checkProtectingSignature(
            final PKIMessage message, final ASN1ObjectIdentifier algorithm, final X509Certificate protectingCert)
            throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
                    CmpValidationException {
        final PKIHeader header = message.getHeader();
        final byte[] protectedBytes = new ProtectedPart(header, message.getBody()).getEncoded(ASN1Encoding.DER);
        final byte[] protectionBytes = message.getProtection().getBytes();
        final Signature sig = Signature.getInstance(algorithm.getId(), CertUtility.getBouncyCastleProvider());
        sig.initVerify(protectingCert.getPublicKey());
        sig.update(protectedBytes);
        if (!sig.verify(protectionBytes, 0, protectionBytes.length)) {
            final String errorDetails = "signature-based protection check failed, signature broken";
            LOGGER.warn(errorDetails);
            throw new CmpValidationException(interfaceName, PKIFailureInfo.wrongIntegrity, errorDetails);
        }
        final ASN1OctetString senderKID = header.getSenderKID();
        if (senderKID == null) {
            LOGGER.warn("missing senderKID in " + MessageDumper.msgTypeAsString(message) + ", ignored");
        } else {
            final DEROctetString kidFromCert = CertUtility.extractSubjectKeyIdentifierFromCert(protectingCert);
            if (kidFromCert != null && !senderKID.equals(kidFromCert)) {
                throw new CmpValidationException(
                        interfaceName,
                        PKIFailureInfo.badMessageCheck,
                        "mismatching senderKID in " + MessageDumper.msgTypeAsString(message));
            }
        }
        final GeneralName sender = header.getSender();

        if (sender != null) {
            final X500Name protectionCertSubject = X500Name.getInstance(
                    protectingCert.getSubjectX500Principal().getEncoded());
            if (sender.getTagNo() != GeneralName.directoryName
                    || !Objects.equals(sender.getName(), protectionCertSubject)) {
                throw new CmpValidationException(
                        interfaceName,
                        PKIFailureInfo.badMessageCheck,
                        "mismatching sender in " + MessageDumper.msgTypeAsString(message));
            }
        }
    }

    @Override
    public Void validate(final PKIMessage message) throws BaseCmpException {
        try {
            final TrustCredentialAdapter trustCredentialAdapter = new TrustCredentialAdapter(config, interfaceName);
            final CMPCertificate[] extraCerts = message.getExtraCerts();
            if (extraCerts != null && extraCerts.length > 0) {
                // extraCerts available, use it for protection check
                final List<X509Certificate> extraCertsAsX509 = CertUtility.asX509Certificates(extraCerts);
                // "extraCerts: If present, the first certificate in this field MUST be the
                // protection certificate"
                final X509Certificate protectingCert = extraCertsAsX509.get(0);
                checkProtectingSignature(
                        message, message.getHeader().getProtectionAlg().getAlgorithm(), protectingCert);
                if (trustCredentialAdapter.validateCertAgainstTrust(protectingCert, extraCertsAsX509) == null) {
                    final String errorDetails = "signature check failed, protecting cert not trusted";
                    LOGGER.warn(errorDetails);
                    throw new CmpValidationException(interfaceName, PKIFailureInfo.signerNotTrusted, errorDetails);
                }
                final boolean[] keyUsage = protectingCert.getKeyUsage();
                if (keyUsage != null && !keyUsage[0] /* digitalSignature */) {
                    // be a little bit more lazy about key usage for protectingCert,
                    // in case of RR or KUR it might be absent.
                    LOGGER.warn("the protecting certificate '" + protectingCert.getSubjectX500Principal()
                            + "' is not valid for digitalSignature, weakness ignored");
                }
                return null;
            }
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final KeyException ex) {
            throw new CmpValidationException(
                    interfaceName, PKIFailureInfo.badAlg, "protecting cert has key not suitable for signing");
        } catch (final Exception ex) {
            throw new CmpProcessingException(
                    interfaceName,
                    PKIFailureInfo.notAuthorized,
                    ex.getClass().getSimpleName() + ":" + ex.getLocalizedMessage());
        }
        throw new CmpValidationException(
                interfaceName,
                PKIFailureInfo.addInfoNotAvailable,
                "signature-based protection check failed, no extraCert provided and no cached protecting cert available");
    }
}
