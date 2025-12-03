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
package com.siemens.pki.cmpracomponent.msggeneration;

import static com.siemens.pki.cmpracomponent.util.NullUtil.computeDefaultIfNull;
import static com.siemens.pki.cmpracomponent.util.NullUtil.defaultIfNull;
import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.cmpracomponent.cryptoservices.DataSigner;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.POPOPrivKey;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

/**
 * a generator for PKI messages conforming to Lightweight CMP Profile <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-lamps-lightweight-cmp-profile/">Lihtweight
 * CMP profile"</a>
 */
public class PkiMessageGenerator {

    /**
     * see rfc4210, D.1.4
     * <p>
     * A constant representing the <code>NULL-DN</code> (NULL distinguished name).
     */
    public static final GeneralName NULL_DN = new GeneralName(new X500Name(new RDN[0]));
    /**
     * the certReqId is always 0
     */
    public static final ASN1Integer CERT_REQ_ID_0 = new ASN1Integer(0);
    /**
     * needed to generate a cert hash
     */
    private static final BcDigestCalculatorProvider BC_DIGEST_CALCULATOR_PROVIDER = new BcDigestCalculatorProvider();

    /**
     * needed to generate a cert hash
     */
    private static final DigestAlgorithmIdentifierFinder DIG_ALG_FINDER = new DefaultDigestAlgorithmIdentifierFinder();

    /**
     * build a {@link HeaderProvider} out the header of a message
     *
     * @param pvno CMP version number to set
     * @param msg  message to use for header rebuilding
     * @return a new build {@link HeaderProvider} holding the MessageTime,
     *         Recipient, RecipNonce, Sender, SenderNonce, TransactionID and
     *         GeneralInfo of the msg
     */
    public static HeaderProvider buildForwardingHeaderProvider(final int pvno, final PKIMessage msg) {
        return new HeaderProvider() {
            private final PKIHeader header = msg.getHeader();

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                return header.getGeneralInfo();
            }

            @Override
            public ASN1GeneralizedTime getMessageTime() {
                return header.getMessageTime();
            }

            @Override
            public int getPvno() {
                return pvno;
            }

            @Override
            public GeneralName getRecipient() {
                return header.getRecipient();
            }

            @Override
            public ASN1OctetString getRecipNonce() {
                return header.getRecipNonce();
            }

            @Override
            public GeneralName getSender() {
                return header.getSender();
            }

            @Override
            public ASN1OctetString getSenderNonce() {
                return header.getSenderNonce();
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return header.getTransactionID();
            }
        };
    }

    /**
     * build a {@link HeaderProvider} out the header of a message
     *
     * @param msg message to use for header rebuilding
     * @return a new build {@link HeaderProvider} holding the MessageTime,
     *         Recipient, RecipNonce, Sender, SenderNonce, TransactionID and
     *         GeneralInfo of the msg
     */
    public static HeaderProvider buildForwardingHeaderProvider(final PKIMessage msg) {
        return buildForwardingHeaderProvider(msg.getHeader().getPvno().intValueExact(), msg);
    }

    /**
     * build a {@link HeaderProvider} for a response to a given message message
     *
     * @param msg message to answer
     * @return a new build {@link HeaderProvider} response holding the MessageTime,
     *         TransactionID, Recipient from Sender, RecipNonce from SenderNonce of
     *         the msg and a fresh SenderNonce
     */
    public static HeaderProvider buildRespondingHeaderProvider(final PKIMessage msg) {
        return new HeaderProvider() {
            final ASN1OctetString senderNonce = new DEROctetString(CertUtility.generateRandomBytes(16));
            private final PKIHeader header = msg.getHeader();

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                return header.getGeneralInfo();
            }

            @Override
            public ASN1GeneralizedTime getMessageTime() {
                return new ASN1GeneralizedTime(new Date());
            }

            @Override
            public int getPvno() {
                final int requestPvno = header.getPvno().intValueExact();
                if (requestPvno < PKIHeader.CMP_2000) {
                    return PKIHeader.CMP_2000;
                }
                if (requestPvno > PKIHeader.CMP_2021) {
                    return PKIHeader.CMP_2021;
                }
                return requestPvno;
            }

            @Override
            public GeneralName getRecipient() {
                return header.getSender();
            }

            @Override
            public ASN1OctetString getRecipNonce() {
                return header.getSenderNonce();
            }

            @Override
            public GeneralName getSender() {
                return null;
            }

            @Override
            public ASN1OctetString getSenderNonce() {
                return senderNonce;
            }

            @Override
            public ASN1OctetString getTransactionID() {
                return header.getTransactionID();
            }
        };
    }

    /**
     * generate and protect a new CMP message
     *
     * @param headerProvider     PKI header
     * @param protectionProvider PKI protection
     * @param newRecipient       outgoing recipient or <code>null</code> if
     *                           recipient from headerProvider should be used
     * @param body               message body
     * @param issuingChain       chain of enrolled certificate to append at the
     *                           extraCerts
     * @return a fully build and protected message
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of encoding error
     */
    public static PKIMessage generateAndProtectMessage(
            final HeaderProvider headerProvider,
            final ProtectionProvider protectionProvider,
            GeneralName newRecipient,
            final PKIBody body,
            final List<CMPCertificate> issuingChain)
            throws GeneralSecurityException, IOException {
        synchronized (protectionProvider) {
            final GeneralName recipient = computeDefaultIfNull(newRecipient, headerProvider::getRecipient);
            final GeneralName sender = computeDefaultIfNull(protectionProvider.getSender(), headerProvider::getSender);
            final PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                    headerProvider.getPvno(), defaultIfNull(sender, NULL_DN), defaultIfNull(recipient, NULL_DN));
            headerBuilder.setMessageTime(headerProvider.getMessageTime());
            headerBuilder.setProtectionAlg(protectionProvider.getProtectionAlg());
            headerBuilder.setSenderKID(protectionProvider.getSenderKID());
            headerBuilder.setTransactionID(headerProvider.getTransactionID());
            headerBuilder.setSenderNonce(headerProvider.getSenderNonce());
            headerBuilder.setRecipNonce(headerProvider.getRecipNonce());
            headerBuilder.setGeneralInfo(headerProvider.getGeneralInfo());
            final PKIHeader generatedHeader = headerBuilder.build();
            final CMPCertificate[] generatedExtraCerts = Stream.concat(
                            defaultIfNull(protectionProvider.getProtectingExtraCerts(), Collections.emptyList())
                                    .stream(),
                            defaultIfNull(issuingChain, Collections.emptyList()).stream())
                    .distinct()
                    .toArray(CMPCertificate[]::new);
            final DERBitString protection =
                    protectionProvider.getProtectionFor(new ProtectedPart(generatedHeader, body));
            return new PKIMessage(
                    generatedHeader, body, protection, generatedExtraCerts.length == 0 ? null : generatedExtraCerts);
        }
    }

    /**
     * generate and protect a new CMP message
     *
     * @param headerProvider     PKI header
     * @param protectionProvider PKI protection
     * @param body               message body
     * @return a fully build and protected message
     * @throws Exception in case of error
     */
    public static PKIMessage generateAndProtectMessage(
            final HeaderProvider headerProvider, final ProtectionProvider protectionProvider, final PKIBody body)
            throws Exception {
        return generateAndProtectMessage(headerProvider, protectionProvider, null, body, null);
    }

    /**
     * generate a CertConf body
     *
     * @param certificate certificate to confirm
     * @return a CertConf body
     * @throws Exception in case of error
     */
    public static PKIBody generateCertConfBody(final CMPCertificate certificate) throws Exception {
        final AlgorithmIdentifier signatureAlgorithm =
                certificate.getX509v3PKCert().getSignatureAlgorithm();
        final AlgorithmIdentifier digAlgFromCert =
                ifNotNull(signatureAlgorithm, x -> DIG_ALG_FINDER.find(signatureAlgorithm));
        final AlgorithmIdentifier digAlgForHash =
                computeDefaultIfNull(digAlgFromCert, () -> new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        final DigestCalculator digester = BC_DIGEST_CALCULATOR_PROVIDER.get(digAlgForHash);
        digester.getOutputStream().write(certificate.getEncoded(ASN1Encoding.DER));
        final ASN1Sequence content = new DERSequence(new CertStatus[] {
            new CertStatus(
                    digester.getDigest(),
                    BigInteger.ZERO,
                    new PKIStatusInfo(PKIStatus.granted),
                    digAlgFromCert != null ? null : digAlgForHash)
        });
        return new PKIBody(PKIBody.TYPE_CERT_CONFIRM, CertConfirmContent.getInstance(content));
    }

    /**
     * generate Error body
     *
     * @param failInfo     failinfo from {@link PKIFailureInfo}
     * @param errorDetails a string describing the problem
     * @return an error body
     */
    public static PKIBody generateErrorBody(final int failInfo, final String errorDetails) {
        final PKIFreeText statusString = ifNotNull(errorDetails, PKIFreeText::new);

        final PKIStatusInfo pkiStatusInfo =
                new PKIStatusInfo(PKIStatus.rejection, statusString, new PKIFailureInfo(failInfo));
        return new PKIBody(PKIBody.TYPE_ERROR, new ErrorMsgContent(pkiStatusInfo, null, statusString));
    }

    /**
     * generate a IP, CP or KUP body for returning a certificate
     *
     * @param bodyType    PKIBody.TYPE_INIT_REP, PKIBody.TYPE_CERT_REP or
     *                    PKIBody.TYPE_KEY_UPDATE_REP
     * @param certificate the certificate to return
     * @return a IP, CP or KUP body
     */
    public static PKIBody generateIpCpKupBody(final int bodyType, final CMPCertificate certificate) {
        final CertResponse[] response = {
            new CertResponse(
                    CERT_REQ_ID_0,
                    new PKIStatusInfo(PKIStatus.granted),
                    new CertifiedKeyPair(new CertOrEncCert(certificate)),
                    null)
        };
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IP, CP or KUP body for returning a certificate and the related
     * private key
     *
     * @param bodyType     PKIBody.TYPE_INIT_REP, PKIBody.TYPE_CERT_REP or
     *                     PKIBody.TYPE_KEY_UPDATE_REP
     * @param certificate  the certificate to return
     * @param privateKey   the private key to return
     * @param keyEncryptor CMS encryptor used for private key transport
     * @param keySigner    CMS signer used for private key transport
     * @return a IP, CP or KUP body
     * @throws Exception    in case of general error
     * @throws CMSException in case of error in CMS processing
     */
    public static PKIBody generateIpCpKupBody(
            final int bodyType,
            final CMPCertificate certificate,
            final PrivateKey privateKey,
            final CmsEncryptorBase keyEncryptor,
            final DataSigner keySigner)
            throws Exception {
        final EncryptedKey encryptedPrivateKey =
                new EncryptedKey(keyEncryptor.encrypt(keySigner.signPrivateKey(privateKey)));
        final CertResponse[] response = {
            new CertResponse(
                    CERT_REQ_ID_0,
                    new PKIStatusInfo(PKIStatus.granted),
                    new CertifiedKeyPair(new CertOrEncCert(certificate), encryptedPrivateKey, null),
                    null)
        };
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IP, CP or KUP body for returning an KEM encrypted cerificate
     *
     * @param bodyType             bodyType PKIBody.TYPE_INIT_REP,
     *                             PKIBody.TYPE_CERT_REP or
     *                             PKIBody.TYPE_KEY_UPDATE_REP
     * @param certificateToEncrypt the certificate to encrypt and return
     * @return a IP, CP or KUP body
     * @throws CertificateEncodingException in case of general error
     * @throws CMSException                 in case of error in CMS processing
     */
    public static PKIBody generateEncryptedIpCpKupBody(final int bodyType, X509Certificate certificateToEncrypt)
            throws CertificateEncodingException, CMSException {
        // encrypt certificate
        // KDF2
        //        AlgorithmIdentifier kdfAlgorithm = new AlgorithmIdentifier(
        //                X9ObjectIdentifiers.id_kdf_kdf2,
        //                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
        // KDF3
        //        AlgorithmIdentifier kdfAlgorithm = new AlgorithmIdentifier(
        //                X9ObjectIdentifiers.id_kdf_kdf3,
        //                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
        // SHAKE256
        AlgorithmIdentifier kdfAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);

        CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();
        // Issuer + serialnumber
        //        JceKEMRecipientInfoGenerator recipientInfoGenerator = new
        // JceKEMRecipientInfoGenerator(certificateToEncrypt, CMSAlgorithm.AES256_WRAP);
        // Subject Pulic Key
        JceKEMRecipientInfoGenerator recipientInfoGenerator = new JceKEMRecipientInfoGenerator(
                certificateToEncrypt.getPublicKey().getEncoded(),
                certificateToEncrypt.getPublicKey(),
                CMSAlgorithm.AES256_WRAP);
        envGen.addRecipientInfoGenerator(recipientInfoGenerator.setKDF(kdfAlgorithm));
        CMSProcessableByteArray content = new CMSProcessableByteArray(certificateToEncrypt.getEncoded());
        final CMSEnvelopedData cmsEnvData = envGen.generate(
                content,
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                        .setProvider(CertUtility.getBouncyCastleProvider())
                        .build());
        EnvelopedData encryptedCertAsEnvelope =
                EnvelopedData.getInstance(cmsEnvData.toASN1Structure().getContent());
        final CertResponse[] response = {
            new CertResponse(
                    PkiMessageGenerator.CERT_REQ_ID_0,
                    new PKIStatusInfo(PKIStatus.granted),
                    new CertifiedKeyPair(new CertOrEncCert(new EncryptedKey(encryptedCertAsEnvelope))),
                    null)
        };
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IP, CP or KUP body containing an error
     *
     * @param bodyType     PKIBody.TYPE_INIT_REP, PKIBody.TYPE_CERT_REP or
     *                     PKIBody.TYPE_KEY_UPDATE_REP
     * @param failInfo     failinfo from {@link PKIFailureInfo}
     * @param errorDetails a string describing the problem
     * @return a IP, CP or KUP body
     */
    public static PKIBody generateIpCpKupErrorBody(final int bodyType, final int failInfo, final String errorDetails) {
        final PKIStatusInfo pkiStatusInfo =
                new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText(errorDetails), new PKIFailureInfo(failInfo));
        final CertResponse[] response = {new CertResponse(CERT_REQ_ID_0, pkiStatusInfo)};
        return new PKIBody(bodyType, new CertRepMessage(null, response));
    }

    /**
     * generate a IR, CR or KUR body
     *
     * @param bodyType     PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_CERT_REQ or
     *                     PKIBody.TYPE_KEY_UPDATE_REQ
     * @param certTemplate template describing the request
     * @param controls     additional controls for KUR
     * @param privateKey   private key to build the POPO, if set to null, POPO is
     *                     set to raVerified
     * @return a IR, CR or KUR body
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of encoding error
     */
    public static PKIBody generateIrCrKurBody(
            final int bodyType, final CertTemplate certTemplate, final Controls controls, final PrivateKey privateKey)
            throws GeneralSecurityException, IOException {
        final CertRequest certReq = new CertRequest(CERT_REQ_ID_0, certTemplate, controls);
        if (privateKey == null) {
            return new PKIBody(bodyType, new CertReqMessages(new CertReqMsg(certReq, new ProofOfPossession(), null)));
        }
        try {
            final Signature sig = AlgorithmHelper.getSignature(AlgorithmHelper.getSigningAlgNameFromKey(privateKey));
            sig.initSign(privateKey);
            sig.update(certReq.getEncoded(ASN1Encoding.DER));
            final ProofOfPossession popo = new ProofOfPossession(new POPOSigningKey(
                    null, AlgorithmHelper.getSigningAlgIdFromKey(privateKey), new DERBitString(sig.sign())));
            return new PKIBody(bodyType, new CertReqMessages(new CertReqMsg(certReq, popo, null)));
        } catch (NoSuchAlgorithmException ex) {
            // POP signing not supported, try KEM
            final ProofOfPossession popo = new ProofOfPossession(
                    ProofOfPossession.TYPE_KEY_ENCIPHERMENT, new POPOPrivKey(SubsequentMessage.encrCert));
            return new PKIBody(bodyType, new CertReqMessages(new CertReqMsg(certReq, popo, null)));
        }
    }

    /**
     * generate a PkiConf body
     *
     * @return a PkiConf body
     */
    public static PKIBody generatePkiConfirmBody() {
        return new PKIBody(PKIBody.TYPE_CONFIRM, new PKIConfirmContent());
    }

    /**
     * generate a PollRep body
     *
     * @param checkAfterTime time in seconds to elapse before a new pollReq may be
     *                       sent by the EE
     * @return a PolRepBody
     */
    public static PKIBody generatePollRep(final int checkAfterTime) {
        return new PKIBody(PKIBody.TYPE_POLL_REP, new PollRepContent(CERT_REQ_ID_0, new ASN1Integer(checkAfterTime)));
    }

    /**
     * generate a PollReq body
     *
     * @return a PollReq body
     */
    public static PKIBody generatePollReq() {
        return new PKIBody(PKIBody.TYPE_POLL_REQ, new PollReqContent(CERT_REQ_ID_0));
    }

    /**
     * generate a response body with a waiting indication
     *
     * @param interfaceName name of processing interface for trace purposes
     * @param requestBody   body of related request
     * @return a IP, CP, KUP or ERROR body
     */
    public static PKIBody generateResponseBodyWithWaiting(final PKIBody requestBody, final String interfaceName) {
        final PKIFreeText errorDetails = new PKIFreeText(
                "delayed delivery of " + MessageDumper.msgTypeAsString(requestBody.getType()) + " at " + interfaceName);
        switch (requestBody.getType()) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ: {
                final CertResponse[] response = {
                    new CertResponse(CERT_REQ_ID_0, new PKIStatusInfo(PKIStatus.waiting, errorDetails), null, null)
                };
                return new PKIBody(requestBody.getType() + 1, new CertRepMessage(null, response));
            }
            case PKIBody.TYPE_P10_CERT_REQ: {
                final CertResponse[] response = {
                    new CertResponse(CERT_REQ_ID_0, new PKIStatusInfo(PKIStatus.waiting, errorDetails), null, null)
                };
                return new PKIBody(PKIBody.TYPE_CERT_REP, new CertRepMessage(null, response));
            }
            default:
                return new PKIBody(
                        PKIBody.TYPE_ERROR, new ErrorMsgContent(new PKIStatusInfo(PKIStatus.waiting, errorDetails)));
        }
    }

    /**
     * generate a RR body
     *
     * @param certificate certificate to revoke
     * @return generated RR body
     * @throws IOException in case of ASN.1 processing errors
     */
    public static PKIBody generateRrBody(final CMPCertificate certificate) throws IOException {

        final Certificate x509v3pkCert = certificate.getX509v3PKCert();
        return generateRrBody(x509v3pkCert.getIssuer(), x509v3pkCert.getSerialNumber());
    }

    /**
     * generate a RR body
     *
     * @param issuer       issuer of certificate to revoke
     * @param serialNumber serialNumber of certificate to revoke
     * @return generated RR body
     * @throws IOException in case of ASN.1 processing errors
     */
    public static PKIBody generateRrBody(final X500Name issuer, final ASN1Integer serialNumber) throws IOException {
        return generateRrBody(issuer, serialNumber, 0);
    }

    /**
     * generate a RR body
     *
     * @param issuer           issuer of certificate to revoke
     * @param serialNumber     serialNumber of certificate to revoke
     * @param revocationReason the reason for this revocation
     * @return generated RR body
     * @throws IOException in case of ASN.1 processing errors
     */
    public static PKIBody generateRrBody(final X500Name issuer, final ASN1Integer serialNumber, int revocationReason)
            throws IOException {
        final CertTemplateBuilder ctb =
                new CertTemplateBuilder().setIssuer(issuer).setSerialNumber(serialNumber);
        final ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(Extension.reasonCode, false, new ASN1Enumerated(revocationReason));
        final RevDetails revDetails = new RevDetails(ctb.build(), extgen.generate());
        return new PKIBody(PKIBody.TYPE_REVOCATION_REQ, new RevReqContent(revDetails));
    }

    /**
     * generate a new unprotected CMP message
     *
     * @param headerProvider PKI header
     * @param body           message body
     * @return a fully build and not protected message
     * @throws GeneralSecurityException in case of error
     * @throws IOException in case of encoding error
     */
    public static PKIMessage generateUnprotectMessage(final HeaderProvider headerProvider, final PKIBody body)
            throws GeneralSecurityException, IOException {
        return generateAndProtectMessage(headerProvider, ProtectionProvider.NO_PROTECTION, null, body, null);
    }

    private PkiMessageGenerator() {}
}
