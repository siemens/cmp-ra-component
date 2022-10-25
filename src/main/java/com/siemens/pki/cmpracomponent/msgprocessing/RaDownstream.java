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
package com.siemens.pki.cmpracomponent.msgprocessing;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.configuration.CheckAndModifyResult;
import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.cryptoservices.CmsEncryptorBase;
import com.siemens.pki.cmpracomponent.cryptoservices.DataSigner;
import com.siemens.pki.cmpracomponent.cryptoservices.KeyAgreementEncryptor;
import com.siemens.pki.cmpracomponent.cryptoservices.KeyPairGeneratorFactory;
import com.siemens.pki.cmpracomponent.cryptoservices.KeyTransportEncryptor;
import com.siemens.pki.cmpracomponent.cryptoservices.PasswordEncryptor;
import com.siemens.pki.cmpracomponent.cryptoservices.TrustCredentialAdapter;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpEnrollmentException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.msgvalidation.InputValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageHeaderValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.ProtectionValidator;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContextManager;
import com.siemens.pki.cmpracomponent.protection.SignatureBasedProtection;
import com.siemens.pki.cmpracomponent.util.MessageDumper;

/**
 * representation of a downstream interface of a RA
 *
 */
class RaDownstream {

    protected static final String INTERFACE_NAME = "downstream";

    private static final Logger LOGGER =
            LoggerFactory.getLogger(RaDownstream.class);

    private static final JcaX509ContentVerifierProviderBuilder X509_CVPB =
            new JcaX509ContentVerifierProviderBuilder();

    private final Collection<Integer> supportedMessageTypes;

    private final Configuration config;

    private final RaUpstream upstreamHandler;

    private final PersistencyContextManager persistencyContextManager;

    /**
     *
     * @param persistencyContextManager
     *            persistency interface
     *
     * @param config
     *            specific configuration
     * @param upstream
     *            related upstream interface handler
     * @param supportedmessagetypes
     *
     * @throws Exception
     *             in case of error
     */
    RaDownstream(final PersistencyContextManager persistencyContextManager,
            final Configuration config, final RaUpstream upstream,
            final Collection<Integer> supportedmessagetypes) {
        this.config = config;
        this.supportedMessageTypes = supportedmessagetypes;
        this.upstreamHandler = upstream;
        this.persistencyContextManager = persistencyContextManager;
    }

    private MsgOutputProtector getOutputProtector(
            final PersistencyContext persistencyContext, final int bodyType)
            throws Exception {
        return new MsgOutputProtector(
                config.getDownstreamConfiguration(ifNotNull(persistencyContext,
                        PersistencyContext::getCertProfile), bodyType),
                INTERFACE_NAME, persistencyContext);
    }

    /**
     * special handling for CR, IR, KUR
     *
     * @param incomingCertificateRequest
     * @param outputProtector
     * @return handled message
     * @throws Exception
     *             in case of error
     */
    private PKIMessage handleCrmfCertificateRequest(
            final PKIMessage incomingCertificateRequest,
            final PersistencyContext persistencyContext) throws Exception {

        final PKIBody requestBody = incomingCertificateRequest.getBody();
        final PKIBody body = requestBody;
        final int requestBodyType = body.getType();
        persistencyContext.setRequestType(requestBodyType);
        final CertReqMsg certReqMsg =
                ((CertReqMessages) body.getContent()).toCertReqMsgArray()[0];
        CertRequest certRequest = certReqMsg.getCertReq();
        CertTemplate certTemplate = certRequest.getCertTemplate();

        // check request against inventory
        final InventoryInterface inventory = config.getInventory(
                persistencyContext.getCertProfile(), requestBodyType);
        if (inventory != null) {
            String requesterDn = null;
            final CMPCertificate[] extraCertsFromDownstreamRequest =
                    incomingCertificateRequest.getExtraCerts();
            if (extraCertsFromDownstreamRequest != null
                    && extraCertsFromDownstreamRequest.length > 0) {
                requesterDn = extraCertsFromDownstreamRequest[0]
                        .getX509v3PKCert().getSubject().toString();
            } else {
                final GeneralName sender =
                        incomingCertificateRequest.getHeader().getSender();
                if (sender != null) {
                    requesterDn = sender.toString();
                }
            }
            final CheckAndModifyResult checkResult =
                    inventory.checkAndModifyCertRequest(
                            persistencyContext.getTransactionId(), requesterDn,
                            certTemplate.getEncoded(),
                            certTemplate.getSubject().toString());

            if (checkResult == null || !checkResult.isGranted()) {
                throw new CmpEnrollmentException(requestBodyType,
                        INTERFACE_NAME, PKIFailureInfo.badCertTemplate,
                        "request refused by external inventory");
            }
            final byte[] updatedCertTemplate =
                    checkResult.getUpdatedCertTemplate();
            if (updatedCertTemplate != null) {
                certTemplate = CertTemplate.getInstance(updatedCertTemplate);
                certRequest = new CertRequest(0, certTemplate,
                        certRequest.getControls());
            }
        }

        // handle central key generation
        final SubjectPublicKeyInfo subjectPublicKeyInfo =
                certTemplate.getPublicKey();
        final Controls controlsInRequest = certRequest.getControls();
        if (subjectPublicKeyInfo == null
                || subjectPublicKeyInfo.getPublicKeyData().getBytes() == null
                || subjectPublicKeyInfo.getPublicKeyData()
                        .getBytes().length == 0) {
            if (incomingCertificateRequest.getHeader().getPvno()
                    .intValueExact() <= PKIHeader.CMP_2000) {
                throw new CmpEnrollmentException(requestBodyType,
                        INTERFACE_NAME, PKIFailureInfo.unsupportedVersion,
                        "requester would not be able to decrypt encrypted key in response, CMP_2021 not supported");
            }
            final KeyPairGenerator kpgen;
            if (subjectPublicKeyInfo != null
                    && subjectPublicKeyInfo.getAlgorithm() != null) {
                // end entity has a preference on the key type to be generated
                final ASN1ObjectIdentifier algorithm =
                        subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
                if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
                    kpgen = KeyPairGeneratorFactory
                            .getEcKeyPairGenerator(subjectPublicKeyInfo
                                    .getAlgorithm().getParameters().toString());
                } else if (EdECObjectIdentifiers.id_Ed448.equals(algorithm)) {
                    kpgen = KeyPairGeneratorFactory
                            .getEdDsaKeyPairGenerator("Ed448");
                } else if (EdECObjectIdentifiers.id_Ed25519.equals(algorithm)) {
                    kpgen = KeyPairGeneratorFactory
                            .getEdDsaKeyPairGenerator("Ed25519");
                } else if (PKCSObjectIdentifiers.rsaEncryption
                        .equals(algorithm)) {
                    final AttributeTypeAndValue[] controls =
                            ifNotNull(controlsInRequest,
                                    Controls::toAttributeTypeAndValueArray);
                    int rsaKeyLen = 2048;
                    if (controls != null) {
                        for (final AttributeTypeAndValue aktControl : controls) {
                            if (CMPObjectIdentifiers.id_regCtrl_rsaKeyLen
                                    .equals(aktControl.getType())) {
                                rsaKeyLen = ASN1Integer
                                        .getInstance(aktControl.getValue())
                                        .getPositiveValue().intValue();
                                break;
                            }
                        }
                    }
                    kpgen = KeyPairGeneratorFactory
                            .getRsaKeyPairGenerator(rsaKeyLen);
                } else {
                    // maybe the JCE can help
                    kpgen = KeyPairGenerator.getInstance(algorithm.getId());
                }
            } else {
                // end entity has no preference on the key type to be generated
                kpgen = KeyPairGeneratorFactory.getRsaKeyPairGenerator(2048);
            }
            final KeyPair keyPair = kpgen.genKeyPair();
            // regenerate template but with newly generated public key
            final CertTemplate certTemplateWithPublicKey =
                    new CertTemplateBuilder()
                            .setSubject(certTemplate.getSubject())
                            .setExtensions(certTemplate.getExtensions())
                            .setPublicKey(SubjectPublicKeyInfo.getInstance(
                                    keyPair.getPublic().getEncoded()))
                            .build();
            final PrivateKey privateKey = keyPair.getPrivate();
            persistencyContext.setNewGeneratedPrivateKey(keyPair.getPrivate());
            // you may use PkiMessageGenerator.buildForwardingHeaderProvider(incomingCertificateRequest), if CA supports CMP2022
            return PkiMessageGenerator.generateUnprotectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(2,
                            incomingCertificateRequest),
                    PkiMessageGenerator.generateIrCrKurBody(
                            PKIBody.TYPE_CERT_REQ, certTemplateWithPublicKey,
                            controlsInRequest,
                            config.getForceRaVerifyOnUpstream(
                                    persistencyContext.getCertProfile(),
                                    requestBodyType) ? null : privateKey));
        }
        final ProofOfPossession popo = certReqMsg.getPopo();
        if (config.getForceRaVerifyOnUpstream(
                persistencyContext.getCertProfile(), requestBodyType)
                || popo == null
                || popo.getType() == ProofOfPossession.TYPE_RA_VERIFIED) {
            // popo invalid or raVerified, regenerate body
            return PkiMessageGenerator.generateUnprotectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(
                            incomingCertificateRequest),
                    PkiMessageGenerator.generateIrCrKurBody(requestBodyType,
                            certTemplate, controlsInRequest, null));
        }

        // initial POPO still there and maybe usable again
        final POPOSigningKey popoSigningKey = (POPOSigningKey) popo.getObject();
        final PublicKey publicKey = KeyFactory.getInstance(
                subjectPublicKeyInfo.getAlgorithm().getAlgorithm().toString(),
                CertUtility.getBouncyCastleProvider())
                .generatePublic(new X509EncodedKeySpec(
                        subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER)));
        final Signature sig = Signature.getInstance(
                popoSigningKey.getAlgorithmIdentifier().getAlgorithm().getId(),
                CertUtility.getBouncyCastleProvider());
        sig.initVerify(publicKey);
        sig.update(certRequest.getEncoded(ASN1Encoding.DER));
        if (sig.verify(popoSigningKey.getSignature().getBytes())) {
            // POPO still valid, continue to use it
            return incomingCertificateRequest;
        }
        // popo unusable, set raVerified
        return PkiMessageGenerator.generateUnprotectMessage(
                PkiMessageGenerator.buildForwardingHeaderProvider(
                        incomingCertificateRequest),
                new PKIBody(requestBodyType,
                        new CertReqMessages(new CertReqMsg(certRequest,
                                new ProofOfPossession(),
                                certReqMsg.getRegInfo()))));
    }

    private PKIMessage handleP10CertificateRequest(
            final PKIMessage incomingP10Request,
            final PersistencyContext persistencyContext)
            throws BaseCmpException {
        try {
            final PKIBody body = incomingP10Request.getBody();
            persistencyContext.setRequestType(body.getType());
            final PKCS10CertificationRequest p10Request =
                    new PKCS10CertificationRequest(
                            (CertificationRequest) body.getContent());
            if (!p10Request.isSignatureValid(
                    X509_CVPB.build(p10Request.getSubjectPublicKeyInfo()))) {
                throw new CmpValidationException(INTERFACE_NAME,
                        PKIFailureInfo.badMessageCheck,
                        "signature of PKCS#10 Request broken");
            }

            // check request against inventory
            final InventoryInterface inventory = config.getInventory(
                    persistencyContext.getCertProfile(), body.getType());
            if (inventory != null) {
                String requesterDn = null;
                final CMPCertificate[] extraCertsFromUpstreamResponse =
                        incomingP10Request.getExtraCerts();
                if (extraCertsFromUpstreamResponse != null
                        && extraCertsFromUpstreamResponse.length > 0) {
                    requesterDn = extraCertsFromUpstreamResponse[0]
                            .getX509v3PKCert().getSubject().toString();
                } else {
                    final GeneralName sender =
                            incomingP10Request.getHeader().getSender();
                    if (sender != null) {
                        requesterDn = sender.toString();
                    }
                }
                if (!inventory.checkP10CertRequest(
                        persistencyContext.getTransactionId(), requesterDn,
                        p10Request.getEncoded(),
                        p10Request.getSubject().toString())) {
                    throw new CmpValidationException(INTERFACE_NAME,
                            PKIFailureInfo.badCertTemplate,
                            "request refused by external inventory");
                }
            }
            return incomingP10Request;
        } catch (final IOException | OperatorCreationException
                | PKCSException e) {
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.badMessageCheck, e);
        }

    }

    private PKIMessage handleValidatedRequest(final PKIMessage incomingRequest,
            final PersistencyContext persistencyContext) throws Exception {
        // request pre processing
        // by default there is no pre processing
        PKIMessage preprocessedRequest = incomingRequest;
        switch (incomingRequest.getBody().getType()) {
        case PKIBody.TYPE_INIT_REQ:
        case PKIBody.TYPE_CERT_REQ:
        case PKIBody.TYPE_KEY_UPDATE_REQ:
            try {
                preprocessedRequest = handleCrmfCertificateRequest(
                        incomingRequest, persistencyContext);
            } catch (final BaseCmpException ex) {
                throw ex;
            } catch (final Exception ex) {
                throw new CmpEnrollmentException(
                        incomingRequest.getBody().getType(), INTERFACE_NAME,
                        PKIFailureInfo.systemFailure, ex.getLocalizedMessage());
            }
            break;
        case PKIBody.TYPE_P10_CERT_REQ:
            preprocessedRequest = handleP10CertificateRequest(incomingRequest,
                    persistencyContext);
            break;
        case PKIBody.TYPE_GEN_MSG:
            //  try to handle locally
            persistencyContext
                    .setRequestType(incomingRequest.getBody().getType());
            final PKIMessage genmResponse = new ServiceImplementation(config)
                    .handleValidatedInputMessage(incomingRequest,
                            persistencyContext);
            if (genmResponse != null) {
                return genmResponse;
            }
            break;
        case PKIBody.TYPE_REVOCATION_REQ:
            persistencyContext
                    .setRequestType(incomingRequest.getBody().getType());
            break;
        default:
        }
        persistencyContext.trackMessage(preprocessedRequest);
        final PKIMessage responseFromUpstream = upstreamHandler
                .handleRequest(preprocessedRequest, persistencyContext);
        persistencyContext.trackMessage(responseFromUpstream);
        // response post processing
        switch (responseFromUpstream.getBody().getType()) {
        case PKIBody.TYPE_INIT_REP:
        case PKIBody.TYPE_CERT_REP:
        case PKIBody.TYPE_KEY_UPDATE_REP:
            return processCertResponse(incomingRequest,
                    preprocessedRequest.getBody().getType(), persistencyContext,
                    responseFromUpstream);
        default:
            // other message type without enrollment chain
            return responseFromUpstream;
        }
    }

    private PKIMessage processCertResponse(final PKIMessage incomingRequest,
            final int preprocessedRequestType,
            final PersistencyContext persistencyContext,
            final PKIMessage responseFromUpstream) throws BaseCmpException {
        try {
            int responseType = responseFromUpstream.getBody().getType();
            final int initialRequestType = persistencyContext.getRequestType();
            // check request <-> response type mapping
            boolean responseTypeOk = false;
            switch (initialRequestType) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
                if (preprocessedRequestType == PKIBody.TYPE_POLL_REQ
                        || responseType - preprocessedRequestType == 1) {
                    responseType = initialRequestType + 1;
                    responseTypeOk = true;
                }
                break;
            case PKIBody.TYPE_P10_CERT_REQ:
                if (responseType == PKIBody.TYPE_CERT_REP) {
                    responseTypeOk = true;
                }
                break;
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                if (responseType == PKIBody.TYPE_CERT_REP
                        || responseType == PKIBody.TYPE_KEY_UPDATE_REP) {
                    responseType = PKIBody.TYPE_KEY_UPDATE_REP;
                    responseTypeOk = true;
                }
                break;
            default:
                throw new CmpProcessingException(INTERFACE_NAME,
                        PKIFailureInfo.systemFailure,
                        "internal error in processCertResponse");
            }
            if (!responseTypeOk) {
                throw new CmpValidationException(INTERFACE_NAME,
                        PKIFailureInfo.badMessageCheck,
                        "unexpected response to certificate request: "
                                + MessageDumper
                                        .msgAsShortString(incomingRequest)
                                + "->" + MessageDumper.msgAsShortString(
                                        responseFromUpstream));
            }
            final CertRepMessage certRep = (CertRepMessage) responseFromUpstream
                    .getBody().getContent();

            final CertResponse certResponse = certRep.getResponse()[0];
            final int pkiStatus =
                    certResponse.getStatus().getStatus().intValue();
            if (pkiStatus != PKIStatus.GRANTED
                    && pkiStatus != PKIStatus.GRANTED_WITH_MODS) {
                // error in response
                return responseFromUpstream;
            }
            final CMPCertificate enrolledCertificate = certResponse
                    .getCertifiedKeyPair().getCertOrEncCert().getCertificate();
            final X509Certificate enrolledCertificateAsX509 =
                    CertUtility.asX509Certificate(enrolledCertificate);
            final TrustCredentialAdapter enrollmentValidator =
                    new TrustCredentialAdapter(config.getEnrollmentTrust(
                            persistencyContext.getCertProfile(), responseType));

            // there is really a certificate and not only an error in the response
            // validate and fix certificate issuing chain
            final List<? extends X509Certificate> issuingChainAsX509 =
                    enrollmentValidator.validateCertAgainstTrust(
                            enrolledCertificateAsX509,
                            ifNotNull(responseFromUpstream.getExtraCerts(),
                                    CertUtility::asX509Certificates));
            if (issuingChainAsX509 == null || issuingChainAsX509.isEmpty()) {
                throw new CmpValidationException(INTERFACE_NAME,
                        PKIFailureInfo.signerNotTrusted,
                        "could not validate trust chain of issued certificate");
            }
            final List<CMPCertificate> issuingChain = issuingChainAsX509
                    .stream().filter(x -> !x.equals(enrolledCertificateAsX509))
                    .map(x -> {
                        try {
                            return CMPCertificate.getInstance(x.getEncoded());
                        } catch (final CertificateEncodingException e) {
                            throw new RuntimeException(e);
                        }
                    }).collect(Collectors.toList());
            persistencyContext.setIssuingChain(issuingChain);

            // update inventory
            ifNotNull(
                    config.getInventory(persistencyContext.getCertProfile(),
                            responseType),
                    x -> x.learnEnrollmentResult(
                            persistencyContext.getTransactionId(),
                            enrolledCertificate.getEncoded(),
                            enrolledCertificateAsX509.getSerialNumber()
                                    .toString(),
                            enrolledCertificateAsX509.getSubjectX500Principal()
                                    .toString(),
                            enrolledCertificateAsX509.getIssuerX500Principal()
                                    .toString()));

            // check for previous central key generation
            final PrivateKey newGeneratedPrivateKey =
                    persistencyContext.getNewGeneratedPrivateKey();
            if (newGeneratedPrivateKey == null) {
                // no central key generation
                return responseFromUpstream;
            }

            // central key generation, respond the private key too
            final CkgContext ckgConfiguration = config.getCkgConfiguration(
                    persistencyContext.getCertProfile(), responseType);

            if (ckgConfiguration == null) {
                throw new CmpEnrollmentException(initialRequestType,
                        INTERFACE_NAME, PKIFailureInfo.notAuthorized,
                        "no credentials for private key signing available");
            }

            final SignatureCredentialContext signingCredentials =
                    ckgConfiguration.getSigningCredentials();
            if (signingCredentials == null) {
                throw new CmpEnrollmentException(initialRequestType,
                        INTERFACE_NAME, PKIFailureInfo.notAuthorized,
                        "central key generation configuration is missing signature credentials");
            }
            final DataSigner keySigner = new DataSigner(
                    new SignatureBasedProtection(signingCredentials));

            final CmsEncryptorBase keyEncryptor =
                    buildEncryptor(incomingRequest, ckgConfiguration,
                            initialRequestType, INTERFACE_NAME);

            final PKIBody responseBodyWithPrivateKey = PkiMessageGenerator
                    .generateIpCpKupBody(responseType, enrolledCertificate,
                            newGeneratedPrivateKey, keyEncryptor, keySigner);
            return PkiMessageGenerator.generateUnprotectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(
                            PKIHeader.CMP_2021, responseFromUpstream),
                    responseBodyWithPrivateKey);
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            LOGGER.warn("could not properly process certificate response", ex);
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.wrongAuthority,
                    "could not properly process certificate response: " + ex);
        }
    }

    protected CmsEncryptorBase buildEncryptor(final PKIMessage incomingRequest,
            final CkgContext ckgConfiguration, final int initialRequestType,
            final String interfaceName) throws GeneralSecurityException,
            CmpProcessingException, CmpEnrollmentException {
        final ASN1ObjectIdentifier protectingAlgOID =
                incomingRequest.getHeader().getProtectionAlg().getAlgorithm();
        if (CMPObjectIdentifiers.passwordBasedMac.equals(protectingAlgOID)
                || PKCSObjectIdentifiers.id_PBMAC1.equals(protectingAlgOID)) {
            return new PasswordEncryptor(ckgConfiguration, initialRequestType,
                    interfaceName);
        }
        final CMPCertificate[] incomingFirstExtraCerts =
                incomingRequest.getExtraCerts();
        if (incomingFirstExtraCerts == null
                || incomingFirstExtraCerts.length < 1) {
            throw new CmpProcessingException(INTERFACE_NAME,
                    PKIFailureInfo.systemUnavail,
                    "could not build key encryption context, no protecting cert in incoming request");
        }
        final X509Certificate recipientCert =
                CertUtility.asX509Certificate(incomingFirstExtraCerts[0]);

        if (recipientCert.getKeyUsage()[4]/* keyAgreement */) {
            return new KeyAgreementEncryptor(ckgConfiguration, recipientCert,
                    initialRequestType, interfaceName);
        }
        // fall back to key transport
        return new KeyTransportEncryptor(ckgConfiguration, recipientCert,
                initialRequestType, interfaceName);
    }

    /**
     * message handler implementation
     *
     * @param in
     *            received message
     * @return message to respond
     */
    PKIMessage handleInputMessage(final PKIMessage in) {
        PersistencyContext persistencyContext = null;
        try {
            try {
                final int inBodyType = in.getBody().getType();
                if (inBodyType == PKIBody.TYPE_NESTED) {
                    final CmpMessageInterface downstreamConfiguration =
                            config.getDownstreamConfiguration(null, inBodyType);
                    final NestedEndpointContext nestedEndpointContext =
                            downstreamConfiguration.getNestedEndpointContext();
                    if (nestedEndpointContext != null) {
                        final String NESTED_STRING = "nested ";
                        final MessageHeaderValidator headerValidator =
                                new MessageHeaderValidator(
                                        NESTED_STRING + INTERFACE_NAME);
                        headerValidator.validate(in);
                        final ProtectionValidator protectionValidator =
                                new ProtectionValidator(
                                        NESTED_STRING + INTERFACE_NAME,
                                        nestedEndpointContext
                                                .getInputVerification());
                        protectionValidator.validate(in);
                        final PKIMessage[] embeddedMessages = PKIMessages
                                .getInstance(in.getBody().getContent())
                                .toPKIMessageArray();
                        if (embeddedMessages == null
                                || embeddedMessages.length == 0) {
                            throw new CmpProcessingException(
                                    NESTED_STRING + INTERFACE_NAME,
                                    PKIFailureInfo.badMessageCheck,
                                    "no embedded messages inside NESTED message");
                        }
                        if (embeddedMessages.length == 1) {
                            return handleInputMessage(embeddedMessages[0]);
                        }
                        final PKIMessage[] responses =
                                Arrays.stream(embeddedMessages)
                                        .map(this::handleInputMessage)
                                        .toArray(PKIMessage[]::new);
                        return getOutputProtector(persistencyContext,
                                PKIBody.TYPE_NESTED).generateAndProtectMessage(
                                        PkiMessageGenerator
                                                .buildRespondingHeaderProvider(
                                                        in),
                                        new PKIBody(PKIBody.TYPE_NESTED,
                                                new PKIMessages(responses)));
                    }
                }
                final InputValidator inputValidator = new InputValidator(
                        INTERFACE_NAME, config::getDownstreamConfiguration,
                        config::isRaVerifiedAcceptable, supportedMessageTypes,
                        persistencyContextManager::loadCreatePersistencyContext);
                persistencyContext = inputValidator.validate(in);
                final PKIMessage responseFromUpstream =
                        handleValidatedRequest(in, persistencyContext);
                // apply downstream protection
                final List<CMPCertificate> issuingChain;
                final int responseBodyType =
                        responseFromUpstream.getBody().getType();
                switch (responseBodyType) {
                case PKIBody.TYPE_INIT_REP:
                case PKIBody.TYPE_CERT_REP:
                case PKIBody.TYPE_KEY_UPDATE_REP:
                    issuingChain = persistencyContext.getIssuingChain();
                    break;
                default:
                    issuingChain = null;

                }
                return getOutputProtector(persistencyContext, responseBodyType)
                        .protectAndForwardMessage(
                                new PKIMessage(responseFromUpstream.getHeader(),
                                        responseFromUpstream.getBody(),
                                        responseFromUpstream.getProtection(),
                                        responseFromUpstream.getExtraCerts()),
                                issuingChain);
            } catch (final BaseCmpException e) {
                final PKIBody errorBody = e.asErrorBody();
                return getOutputProtector(persistencyContext,
                        errorBody.getType())
                                .generateAndProtectMessage(PkiMessageGenerator
                                        .buildRespondingHeaderProvider(in),
                                        errorBody);
            } catch (final RuntimeException ex) {
                final PKIBody errorBody =
                        new CmpProcessingException(INTERFACE_NAME, ex)
                                .asErrorBody();
                return getOutputProtector(persistencyContext,
                        errorBody.getType())
                                .generateAndProtectMessage(PkiMessageGenerator
                                        .buildRespondingHeaderProvider(in),
                                        errorBody);
            } finally {
                if (persistencyContext != null) {
                    persistencyContext.flush();
                }
            }
        } catch (final Exception ex) {
            LOGGER.error("fatal exception at " + INTERFACE_NAME, ex);
            throw new RuntimeException("fatal exception at " + INTERFACE_NAME,
                    ex);
        }
    }
}
