/*
 *  Copyright (c) 2026 Siemens AG
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
package com.siemens.pki.cmpracomponent.testutil.req;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CrmfAndCmpFactory {
    private static final SecureRandom RNG = new SecureRandom();

    // ---------------------------------------------------------------------
    // A) EE builds CRMF CertificateRequestMessage with POP=signature
    // ---------------------------------------------------------------------
    public static CertificateRequestMessage buildCrmfForEe(
            KeyPair eeKeys, X500Name subject, Extensions requestedExtensions) throws Exception {

        // Use a random certReqId
        BigInteger certReqId = new BigInteger(64, RNG).abs();

        JcaCertificateRequestMessageBuilder b = new JcaCertificateRequestMessageBuilder(certReqId);

        // Set subject via X500Principal → X500Name
        b.setSubject(new X500Principal(subject.toString()));

        // Use the Jca builder's convenience function
        b.setPublicKey(eeKeys.getPublic());

        // Attach requested X.509v3 extensions (SAN, EKU, KU, BC, ...)
        if (requestedExtensions != null) {
            for (ASN1ObjectIdentifier oid : requestedExtensions.getExtensionOIDs()) {
                Extension ext = requestedExtensions.getExtension(oid);
                b.addExtension(oid, ext.isCritical(), ext.getParsedValue());
            }
        }

        // Proof-of-possession: sign the CRMF with the key corresponding to the public key
        ContentSigner popSigner = new JcaContentSignerBuilder("SHA256withRSA").build(eeKeys.getPrivate());
        b.setProofOfPossessionSigningKeySigner(popSigner);

        return b.build();
    }

    // ---------------------------------------------------------------------
    // B) Wrap CRMF in a CMP ir protected with PBM (shared secret with RA/CA)
    // => typical for EE_newPKI
    // ---------------------------------------------------------------------
    public static ProtectedPKIMessage buildCmpIrToRaPBM(
            CertificateRequestMessage crmf,
            X500Name eeSender, // EE Distinguished Name (can be same as subject)
            X500Name raRecipient, // RA Distinguished Name
            char[] sharedSecret // PBM secret (MAC protection)
            ) throws Exception {

        GeneralName sender = new GeneralName(eeSender);
        GeneralName recipient = new GeneralName(raRecipient);

        ProtectedPKIMessageBuilder pb = new ProtectedPKIMessageBuilder(sender, recipient);

        pb.setMessageTime(new Date());
        pb.setSenderNonce(randomBytes(16));
        pb.setTransactionID(randomBytes(16));

        // CMP body: Initialization Request (ir) with a single CRMF
        CertReqMsg asn1Req = crmf.toASN1Structure();
        pb.setBody(new PKIBody(PKIBody.TYPE_INIT_REQ, new CertReqMessages(asn1Req)));

        byte[] salt = randomBytes(20); // default saltLength is 20
        int iterationCount = 2048;

        // or NIST SHA-256 if available
        AlgorithmIdentifier owfAlgId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);

        AlgorithmIdentifier macAlgId = new AlgorithmIdentifier(IANAObjectIdentifiers.hmacSHA1, DERNull.INSTANCE);

        PBMParameter params = new PBMParameter(salt, owfAlgId, iterationCount, macAlgId);

        PKMACBuilder pkMacBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());

        pkMacBuilder.setParameters(params);

        // Build PBM MAC calculator
        MacCalculator macCalculator = pkMacBuilder.build(sharedSecret);

        // Build final protected message
        return pb.build(macCalculator);
    }

    // ---------------------------------------------------------------------
    // C) Wrap CRMF in a CMP ir protected with a signature (EE already has cert)
    // => typical for EE_knownPKI or renewal flows
    // ---------------------------------------------------------------------
    public static ProtectedPKIMessage buildCmpIrToRaSigned(
            CertificateRequestMessage crmf,
            X500Name eeSender,
            X500Name raRecipient,
            PrivateKey signerKey,
            X509Certificate signerCert)
            throws Exception {

        GeneralName sender = new GeneralName(eeSender);
        GeneralName recipient = new GeneralName(raRecipient);

        ProtectedPKIMessageBuilder pb = new ProtectedPKIMessageBuilder(sender, recipient);

        pb.setMessageTime(new Date());
        pb.setSenderNonce(randomBytes(16));
        pb.setTransactionID(randomBytes(16));

        // Add CRMF request
        CertReqMsg req = crmf.toASN1Structure();
        pb.setBody(new PKIBody(PKIBody.TYPE_INIT_REQ, new CertReqMessages(req)));

        // Add signer certificate to extraCerts list
        pb.addCMPCertificate(new X509CertificateHolder(signerCert.getEncoded()));

        // Build signature-based CMP protection
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signerKey);

        return pb.build(signer);
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------
    private static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        RNG.nextBytes(out);
        return out;
    }
}
