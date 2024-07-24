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
import com.siemens.pki.cmpracomponent.msggeneration.MsgOutputProtector;
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
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.cmpracomponent.util.NullUtil.ExFunction;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
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
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * representation of a downstream interface of a RA
 */
class RaDownstream {

    private static <T, R, E extends Exception> Function<T, R> wrap(ExFunction<T, R, E> checkedFunction) {
        return t -> {
            try {
                return checkedFunction.apply(t);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    private static final String INTERFACE_NAME = "downstream";

    private static final String NESTED_INTERFACE_NAME = "nested " + INTERFACE_NAME;

    private static final Logger LOGGER = LoggerFactory.getLogger(RaDownstream.class);

    private static final JcaX509ContentVerifierProviderBuilder X509_CVPB =
            new JcaX509ContentVerifierProviderBuilder().setProvider(CertUtility.getBouncyCastleProvider());

    private final Collection<Integer> supportedMessageTypes;

    private final Configuration config;

    private final RaUpstream upstreamHandler;

    private final PersistencyContextManager persistencyContextManager;

    /**
     * @param persistencyContextManager persistency interface
     * @param config                    specific configuration
     * @param upstream                  related upstream interface handler
     * @param supportedmessagetypes
     */
    RaDownstream(
            final PersistencyContextManager persistencyContextManager,
            final Configuration config,
            final RaUpstream upstream,
            final Collection<Integer> supportedmessagetypes) {
        this.config = config;
        this.supportedMessageTypes = supportedmessagetypes;
        this.upstreamHandler = upstream;
        this.persistencyContextManager = persistencyContextManager;
    }

    protected CmsEncryptorBase buildEncryptor(
            final PKIMessage incomingRequest,
            final CkgContext ckgConfiguration,
            final int initialRequestType,
            final String interfaceName)
            throws GeneralSecurityException, BaseCmpException {
        final ASN1ObjectIdentifier protectingAlgOID =
                incomingRequest.getHeader().getProtectionAlg().getAlgorithm();
        if (CMPObjectIdentifiers.passwordBasedMac.equals(protectingAlgOID)
                || PKCSObjectIdentifiers.id_PBMAC1.equals(protectingAlgOID)) {
            return new PasswordEncryptor(ckgConfiguration, initialRequestType, interfaceName);
        }
        final CMPCertificate[] incomingFirstExtraCerts = incomingRequest.getExtraCerts();
        if (incomingFirstExtraCerts == null || incomingFirstExtraCerts.length < 1) {
            throw new CmpProcessingException(
                    INTERFACE_NAME,
                    PKIFailureInfo.systemUnavail,
                    "could not build key encryption context, no protecting cert in incoming request");
        }
        final X509Certificate recipientCert = CertUtility.asX509Certificate(incomingFirstExtraCerts[0]);

        final boolean[] keyUsage = recipientCert.getKeyUsage();
        if (keyUsage == null) {
            if ("RSA".equals(recipientCert.getPublicKey().getAlgorithm())) {
                return new KeyTransportEncryptor(ckgConfiguration, recipientCert, initialRequestType, interfaceName);
            }
            return new KeyAgreementEncryptor(ckgConfiguration, recipientCert, initialRequestType, interfaceName);
        }
        if (keyUsage[4] /* keyAgreement */) {
            return new KeyAgreementEncryptor(ckgConfiguration, recipientCert, initialRequestType, interfaceName);
        }
        // fall back to key transport
        return new KeyTransportEncryptor(ckgConfiguration, recipientCert, initialRequestType, interfaceName);
    }

    // special handling for CR, IR, KUR
    private PKIMessage handleCrmfCertificateRequest(
            final PKIMessage incomingCertificateRequest, final PersistencyContext persistencyContext)
            throws BaseCmpException, GeneralSecurityException, IOException {

        final PKIBody requestBody = incomingCertificateRequest.getBody();
        final PKIBody body = requestBody;
        final int requestBodyType = body.getType();
        persistencyContext.setRequestType(requestBodyType);
        final CertReqMsg certReqMsg = ((CertReqMessages) body.getContent()).toCertReqMsgArray()[0];
        CertRequest certRequest = certReqMsg.getCertReq();
        CertTemplate certTemplate = certRequest.getCertTemplate();

        // check request against inventory
        final InventoryInterface inventory = ConfigLogger.logOptional(
                INTERFACE_NAME,
                "Configuration.getInventory",
                config::getInventory,
                persistencyContext.getCertProfile(),
                requestBodyType);
        if (inventory != null) {
            String requesterDn = null;
            final CMPCertificate[] extraCertsFromDownstreamRequest = incomingCertificateRequest.getExtraCerts();
            if (extraCertsFromDownstreamRequest != null && extraCertsFromDownstreamRequest.length > 0) {
                requesterDn = extraCertsFromDownstreamRequest[0]
                        .getX509v3PKCert()
                        .getSubject()
                        .toString();
            } else {
                final GeneralName sender =
                        incomingCertificateRequest.getHeader().getSender();
                if (sender != null) {
                    requesterDn = sender.toString();
                }
            }
            final String requesterDnFinal = requesterDn;
            final CertTemplate certTemplateFinal = certTemplate;
            byte[] encodedTemplate = certTemplateFinal.getEncoded();
            byte[] encodedRequest = incomingCertificateRequest.getEncoded();
            final CheckAndModifyResult checkResult = ConfigLogger.logOptional(
                    INTERFACE_NAME,
                    "InventoryInterface.checkAndModifyCertRequest(byte[], String, byte[], String, byte[])",
                    () -> inventory.checkAndModifyCertRequest(
                            persistencyContext.getTransactionId(),
                            requesterDnFinal,
                            encodedTemplate,
                            ifNotNull(certTemplateFinal.getSubject(), X500Name::toString),
                            encodedRequest));

            if (checkResult == null
                    || !ConfigLogger.log(INTERFACE_NAME, "CheckAndModifyResult.isGranted()", checkResult::isGranted)) {
                throw new CmpEnrollmentException(
                        requestBodyType,
                        INTERFACE_NAME,
                        PKIFailureInfo.badCertTemplate,
                        "request refused by external inventory");
            }
            final byte[] updatedCertTemplate = ConfigLogger.logOptional(
                    INTERFACE_NAME,
                    "CheckAndModifyResult.getUpdatedCertTemplate()",
                    checkResult::getUpdatedCertTemplate);
            if (updatedCertTemplate != null) {
                certTemplate = CertTemplate.getInstance(updatedCertTemplate);
                certRequest = new CertRequest(0, certTemplate, certRequest.getControls());
            }
        }

        // handle central key generation
        final SubjectPublicKeyInfo subjectPublicKeyInfo = certTemplate.getPublicKey();
        final Controls controlsInRequest = certRequest.getControls();
        if (subjectPublicKeyInfo == null
                || subjectPublicKeyInfo.getPublicKeyData().getBytes() == null
                || subjectPublicKeyInfo.getPublicKeyData().getBytes().length == 0) {
            if (incomingCertificateRequest.getHeader().getPvno().intValueExact() <= PKIHeader.CMP_2000) {
                throw new CmpEnrollmentException(
                        requestBodyType,
                        INTERFACE_NAME,
                        PKIFailureInfo.unsupportedVersion,
                        "requester would not be able to decrypt encrypted key in response, CMP_2021 not supported");
            }
            final KeyPairGenerator kpgen;
            if (subjectPublicKeyInfo != null && subjectPublicKeyInfo.getAlgorithm() != null) {
                // end entity has a preference on the key type to be generated
                final ASN1ObjectIdentifier algorithm =
                        subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
                if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
                    kpgen = KeyPairGeneratorFactory.getEcKeyPairGenerator(
                            subjectPublicKeyInfo.getAlgorithm().getParameters().toString());
                } else if (EdECObjectIdentifiers.id_Ed448.equals(algorithm)) {
                    kpgen = KeyPairGeneratorFactory.getEdDsaKeyPairGenerator("Ed448");
                } else if (EdECObjectIdentifiers.id_Ed25519.equals(algorithm)) {
                    kpgen = KeyPairGeneratorFactory.getEdDsaKeyPairGenerator("Ed25519");
                } else if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)) {
                    final AttributeTypeAndValue[] controls =
                            ifNotNull(controlsInRequest, Controls::toAttributeTypeAndValueArray);
                    int rsaKeyLen = 2048;
                    if (controls != null) {
                        for (final AttributeTypeAndValue aktControl : controls) {
                            if (CMPObjectIdentifiers.id_regCtrl_rsaKeyLen.equals(aktControl.getType())) {
                                rsaKeyLen = ASN1Integer.getInstance(aktControl.getValue())
                                        .getPositiveValue()
                                        .intValue();
                                break;
                            }
                        }
                    }
                    kpgen = KeyPairGeneratorFactory.getRsaKeyPairGenerator(rsaKeyLen);
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
            final CertTemplate certTemplateWithPublicKey = new CertTemplateBuilder()
                    .setSubject(certTemplate.getSubject())
                    .setExtensions(certTemplate.getExtensions())
                    .setPublicKey(
                            SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                    .build();
            final PrivateKey privateKey = keyPair.getPrivate();
            persistencyContext.setNewGeneratedPrivateKey(keyPair.getPrivate());
            // you may use
            // PkiMessageGenerator.buildForwardingHeaderProvider(incomingCertificateRequest),
            // if CA supports
            // CMP2022
            return PkiMessageGenerator.generateUnprotectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(2, incomingCertificateRequest),
                    PkiMessageGenerator.generateIrCrKurBody(
                            PKIBody.TYPE_CERT_REQ,
                            certTemplateWithPublicKey,
                            controlsInRequest,
                            ConfigLogger.log(
                                            INTERFACE_NAME,
                                            "Configuration.getForceRaVerifyOnUpstream",
                                            config::getForceRaVerifyOnUpstream,
                                            persistencyContext.getCertProfile(),
                                            requestBodyType)
                                    ? null
                                    : privateKey));
        }
        final ProofOfPossession popo = certReqMsg.getPop();
        if (ConfigLogger.log(
                        INTERFACE_NAME,
                        "Configuration.getForceRaVerifyOnUpstream",
                        config::getForceRaVerifyOnUpstream,
                        persistencyContext.getCertProfile(),
                        requestBodyType)
                || popo == null
                || popo.getType() == ProofOfPossession.TYPE_RA_VERIFIED) {
            // popo invalid or raVerified, regenerate body
            return PkiMessageGenerator.generateUnprotectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(incomingCertificateRequest),
                    PkiMessageGenerator.generateIrCrKurBody(requestBodyType, certTemplate, controlsInRequest, null));
        }

        // initial POPO still there and maybe usable again
        final POPOSigningKey popoSigningKey = (POPOSigningKey) popo.getObject();
        final PublicKey publicKey = KeyFactory.getInstance(
                        subjectPublicKeyInfo.getAlgorithm().getAlgorithm().toString(),
                        CertUtility.getBouncyCastleProvider())
                .generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER)));
        final Signature sig = Signature.getInstance(
                popoSigningKey.getAlgorithmIdentifier().getAlgorithm().getId(), CertUtility.getBouncyCastleProvider());
        sig.initVerify(publicKey);
        sig.update(certRequest.getEncoded(ASN1Encoding.DER));
        if (sig.verify(popoSigningKey.getSignature().getBytes())) {
            // POPO still valid, continue to use it
            return incomingCertificateRequest;
        }
        // popo unusable, set raVerified
        return PkiMessageGenerator.generateUnprotectMessage(
                PkiMessageGenerator.buildForwardingHeaderProvider(incomingCertificateRequest),
                new PKIBody(
                        requestBodyType,
                        new CertReqMessages(
                                new CertReqMsg(certRequest, new ProofOfPossession(), certReqMsg.getRegInfo()))));
    }

    /**
     * message handler implementation
     *
     * @param in received message
     * @return message to respond
     */
    PKIMessage handleInputMessage(final PKIMessage in) {
        PersistencyContext persistencyContext = null;
        int responseBodyType = PKIBody.TYPE_ERROR;
        int retryAfterTime = 0;
        try {
            try {
                byte[] transactionId =
                        ifNotNull(in, m -> m.getHeader().getTransactionID().getOctets());
                if (transactionId == null) {
                    MsgOutputProtector protector = new MsgOutputProtector(
                            ConfigLogger.log(
                                    INTERFACE_NAME,
                                    "Configuration.getDownstreamConfiguration",
                                    config::getDownstreamConfiguration,
                                    null,
                                    PKIBody.TYPE_ERROR),
                            INTERFACE_NAME,
                            null);
                    return protector.generateAndProtectResponseTo(
                            in,
                            PkiMessageGenerator.generateErrorBody(
                                    PKIFailureInfo.badDataFormat, "transactionId missing"));
                }
                persistencyContext = persistencyContextManager.loadCreatePersistencyContext(transactionId);
                final int inBodyType = in.getBody().getType();
                if (inBodyType == PKIBody.TYPE_NESTED) {
                    PersistencyContext nestedPersistencyContext = persistencyContext;
                    // suppress persistency update for NESTED messages
                    persistencyContext = null;
                    return handleNestedRequest(in, nestedPersistencyContext);
                }
                final InputValidator inputValidator = new InputValidator(
                        INTERFACE_NAME,
                        config::getDownstreamConfiguration,
                        config::isRaVerifiedAcceptable,
                        supportedMessageTypes,
                        persistencyContext);
                inputValidator.validate(in);

                PKIMessage responseFromUpstream = handleValidatedRequest(in, persistencyContext);
                // apply downstream protection and nesting
                List<CMPCertificate> issuingChain = null;
                responseBodyType = responseFromUpstream.getBody().getType();
                switch (responseBodyType) {
                    case PKIBody.TYPE_NESTED:
                        // never nest a nested message
                        persistencyContext = null;
                        return responseFromUpstream;
                    case PKIBody.TYPE_INIT_REP:
                    case PKIBody.TYPE_CERT_REP:
                    case PKIBody.TYPE_KEY_UPDATE_REP:
                        issuingChain = persistencyContext.getIssuingChain();
                        break;
                    case PKIBody.TYPE_POLL_REP:
                        retryAfterTime = ((PollRepContent)
                                        responseFromUpstream.getBody().getContent())
                                .getCheckAfter(0)
                                .intPositiveValueExact();
                        break;
                    default:
                }
                final CmpMessageInterface downstreamConfiguration = ConfigLogger.log(
                        INTERFACE_NAME,
                        "Configuration.getDownstreamConfiguration",
                        config::getDownstreamConfiguration,
                        ifNotNull(persistencyContext, PersistencyContext::getCertProfile),
                        responseBodyType);
                PKIMessage protectedResponse = new MsgOutputProtector(
                                downstreamConfiguration, INTERFACE_NAME, persistencyContext)
                        .protectOutgoingMessage(
                                new PKIMessage(
                                        responseFromUpstream.getHeader(),
                                        responseFromUpstream.getBody(),
                                        responseFromUpstream.getProtection(),
                                        responseFromUpstream.getExtraCerts()),
                                issuingChain);

                final NestedEndpointContext nestedEndpointContext = ConfigLogger.logOptional(
                        INTERFACE_NAME,
                        "CmpMessageInterface.getNestedEndpointContext()",
                        downstreamConfiguration::getNestedEndpointContext);
                if (nestedEndpointContext == null) {
                    // no nesting required
                    return protectedResponse;
                }
                return new MsgOutputProtector(nestedEndpointContext, NESTED_INTERFACE_NAME)
                        .createOutgoingMessage(
                                PkiMessageGenerator.buildForwardingHeaderProvider(protectedResponse),
                                new PKIBody(PKIBody.TYPE_NESTED, new PKIMessages(protectedResponse)));
            } catch (final BaseCmpException e) {
                final PKIBody errorBody = e.asErrorBody();
                final CmpMessageInterface downstreamConfiguration = ConfigLogger.log(
                        INTERFACE_NAME,
                        "Configuration.getDownstreamConfiguration",
                        config::getDownstreamConfiguration,
                        ifNotNull(persistencyContext, PersistencyContext::getCertProfile),
                        errorBody.getType());
                return new MsgOutputProtector(downstreamConfiguration, INTERFACE_NAME, persistencyContext)
                        .generateAndProtectResponseTo(in, errorBody);
            } catch (final RuntimeException ex) {
                final PKIBody errorBody = new CmpProcessingException(INTERFACE_NAME, ex).asErrorBody();
                final CmpMessageInterface downstreamConfiguration = ConfigLogger.log(
                        INTERFACE_NAME,
                        "Configuration.getDownstreamConfiguration",
                        config::getDownstreamConfiguration,
                        ifNotNull(persistencyContext, PersistencyContext::getCertProfile),
                        errorBody.getType());
                return new MsgOutputProtector(downstreamConfiguration, INTERFACE_NAME, persistencyContext)
                        .generateAndProtectResponseTo(in, errorBody);
            } finally {
                if (persistencyContext != null) {
                    int offset = ConfigLogger.log(
                            INTERFACE_NAME,
                            "Configuration.getDownstreamTimeout",
                            config::getDownstreamTimeout,
                            persistencyContext.getCertProfile(),
                            responseBodyType);
                    if (offset == 0) {
                        offset = Integer.MAX_VALUE / 2;
                    }
                    persistencyContext.updateTransactionExpirationTime(
                            new Date(System.currentTimeMillis() + (offset + retryAfterTime) * 1000L));
                    persistencyContext.flush();
                }
            }
        } catch (final Exception ex) {
            LOGGER.error("fatal exception at " + INTERFACE_NAME, ex);
            throw new RuntimeException("fatal exception at " + INTERFACE_NAME, ex);
        }
    }

    private PKIMessage handleNestedRequest(final PKIMessage in, final PersistencyContext persistencyContext)
            throws BaseCmpException, GeneralSecurityException, IOException {
        final CmpMessageInterface downstreamConfiguration = ConfigLogger.log(
                INTERFACE_NAME,
                "Configuration.getDownstreamConfiguration",
                config::getDownstreamConfiguration,
                null,
                PKIBody.TYPE_NESTED);
        final NestedEndpointContext nestedEndpointContext = ConfigLogger.logOptional(
                INTERFACE_NAME,
                "CmpMessageInterface.getNestedEndpointContext()",
                downstreamConfiguration::getNestedEndpointContext);
        if (nestedEndpointContext == null) {
            return upstreamHandler.handleRequest(in, persistencyContext);
        }
        final MessageHeaderValidator nestedHeaderValidator = new MessageHeaderValidator(NESTED_INTERFACE_NAME);
        nestedHeaderValidator.validate(in);
        final ProtectionValidator nestedProtectionValidator = new ProtectionValidator(
                NESTED_INTERFACE_NAME,
                ConfigLogger.logOptional(
                        NESTED_INTERFACE_NAME,
                        "NestedEndpointContext.getInputVerification()",
                        nestedEndpointContext::getInputVerification));
        nestedProtectionValidator.validate(in);
        PKIHeader inHeader = in.getHeader();
        boolean isIncomingRecipientValid = ConfigLogger.log(
                NESTED_INTERFACE_NAME,
                "NestedEndpointContext.isIncomingRecipientValid()",
                () -> nestedEndpointContext.isIncomingRecipientValid(
                        inHeader.getRecipient().getName().toString()));
        if (!isIncomingRecipientValid) {
            return upstreamHandler.handleRequest(in, persistencyContext);
        }
        final PKIMessage[] embeddedMessages =
                PKIMessages.getInstance(in.getBody().getContent()).toPKIMessageArray();
        if (embeddedMessages == null || embeddedMessages.length == 0) {
            throw new CmpProcessingException(
                    NESTED_INTERFACE_NAME,
                    PKIFailureInfo.badMessageCheck,
                    "no embedded messages inside NESTED message");
        }
        // wrapped protection case
        if (embeddedMessages.length == 1) {
            return handleInputMessage(embeddedMessages[0]);
        }
        // batching
        final PKIMessage[] responses =
                Arrays.stream(embeddedMessages).map(this::handleInputMessage).toArray(PKIMessage[]::new);
        // batched responses needs to be wrapped in a new NESTED response
        MsgOutputProtector nestedOutputProtector = new MsgOutputProtector(nestedEndpointContext, INTERFACE_NAME);
        return nestedOutputProtector.generateAndProtectResponseTo(
                in, new PKIBody(PKIBody.TYPE_NESTED, new PKIMessages(responses)));
    }

    private PKIMessage handleP10CertificateRequest(
            final PKIMessage incomingP10Request, final PersistencyContext persistencyContext)
            throws BaseCmpException, IOException {
        try {
            final PKIBody body = incomingP10Request.getBody();
            persistencyContext.setRequestType(body.getType());
            final PKCS10CertificationRequest p10Request =
                    new PKCS10CertificationRequest((CertificationRequest) body.getContent());
            if (!p10Request.isSignatureValid(X509_CVPB.build(p10Request.getSubjectPublicKeyInfo()))) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badMessageCheck, "signature of PKCS#10 Request broken");
            }

            // check request against inventory
            final InventoryInterface inventory = ConfigLogger.logOptional(
                    INTERFACE_NAME,
                    "Configuration.getInventory",
                    config::getInventory,
                    persistencyContext.getCertProfile(),
                    body.getType());
            if (inventory != null) {
                String requesterDn = null;
                final CMPCertificate[] extraCertsFromUpstreamResponse = incomingP10Request.getExtraCerts();
                if (extraCertsFromUpstreamResponse != null && extraCertsFromUpstreamResponse.length > 0) {
                    requesterDn = extraCertsFromUpstreamResponse[0]
                            .getX509v3PKCert()
                            .getSubject()
                            .toString();
                } else {
                    final GeneralName sender = incomingP10Request.getHeader().getSender();
                    if (sender != null) {
                        requesterDn = sender.toString();
                    }
                }
                final byte[] encodedP10Request = p10Request.getEncoded();
                final byte[] encodedIncomingP10Request = incomingP10Request.getEncoded();
                final String requesterDnFinal = requesterDn;
                if (!ConfigLogger.log(
                        INTERFACE_NAME,
                        "InventoryInterface.checkP10CertRequest(byte[], String, byte[], String, byte[])",
                        () -> inventory.checkP10CertRequest(
                                persistencyContext.getTransactionId(),
                                requesterDnFinal,
                                encodedP10Request,
                                p10Request.getSubject().toString(),
                                encodedIncomingP10Request))) {
                    throw new CmpValidationException(
                            INTERFACE_NAME, PKIFailureInfo.badCertTemplate, "request refused by external inventory");
                }
            }
            return incomingP10Request;
        } catch (final OperatorCreationException | PKCSException e) {
            throw new CmpProcessingException(INTERFACE_NAME, PKIFailureInfo.badMessageCheck, e);
        }
    }

    private PKIMessage handleRevocationRequest(PKIMessage incomingRequest, PersistencyContext persistencyContext)
            throws BaseCmpException, IOException {
        final PKIBody body = incomingRequest.getBody();
        final int requestType = body.getType();
        persistencyContext.setRequestType(requestType);
        final InventoryInterface inventory = ConfigLogger.logOptional(
                INTERFACE_NAME,
                "Configuration.getInventory",
                config::getInventory,
                persistencyContext.getCertProfile(),
                requestType);
        if (inventory != null) {
            final CertTemplate revTemplate =
                    ((RevReqContent) body.getContent()).toRevDetailsArray()[0].getCertDetails();
            final byte[] encodedIncomingRequest = incomingRequest.getEncoded();
            if (!ConfigLogger.log(
                    INTERFACE_NAME,
                    "InventoryInterface.checkRevocationRequest(byte[], String, String, String, byte[])",
                    () -> inventory.checkRevocationRequest(
                            persistencyContext.getTransactionId(),
                            ifNotNull(incomingRequest.getHeader().getSender(), sender -> X500Name.getInstance(
                                            sender.getName())
                                    .toString()),
                            ifNotNull(revTemplate, template -> template.getSerialNumber()
                                    .toString()),
                            ifNotNull(revTemplate, template -> template.getIssuer()
                                    .toString()),
                            encodedIncomingRequest))) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badRequest, "request refused by external inventory");
            }
        }
        return incomingRequest;
    }

    private PKIMessage handleValidatedRequest(
            final PKIMessage incomingRequest, final PersistencyContext persistencyContext)
            throws BaseCmpException, IOException {
        // request pre processing
        // by default there is no pre processing
        PKIMessage preprocessedRequest = incomingRequest;
        switch (incomingRequest.getBody().getType()) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                try {
                    preprocessedRequest = handleCrmfCertificateRequest(incomingRequest, persistencyContext);
                } catch (final BaseCmpException ex) {
                    throw ex;
                } catch (final Exception ex) {
                    throw new CmpEnrollmentException(
                            incomingRequest.getBody().getType(),
                            INTERFACE_NAME,
                            PKIFailureInfo.systemFailure,
                            ex.getLocalizedMessage());
                }
                break;
            case PKIBody.TYPE_P10_CERT_REQ:
                preprocessedRequest = handleP10CertificateRequest(incomingRequest, persistencyContext);
                break;
            case PKIBody.TYPE_REVOCATION_REQ:
                preprocessedRequest = handleRevocationRequest(incomingRequest, persistencyContext);
                break;
            case PKIBody.TYPE_GEN_MSG:
                // try to handle locally
                persistencyContext.setRequestType(incomingRequest.getBody().getType());
                final PKIMessage genmResponse = new ServiceImplementation(config)
                        .handleValidatedInputMessage(incomingRequest, persistencyContext);
                if (genmResponse != null) {
                    return genmResponse;
                }
                break;
            default:
        }
        persistencyContext.trackMessage(preprocessedRequest);
        final PKIMessage responseFromUpstream = upstreamHandler.handleRequest(preprocessedRequest, persistencyContext);
        persistencyContext.trackMessage(responseFromUpstream);
        // response post processing
        switch (responseFromUpstream.getBody().getType()) {
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP:
                return processCertResponse(
                        incomingRequest,
                        preprocessedRequest.getBody().getType(),
                        persistencyContext,
                        responseFromUpstream);
            default:
                // other message type without enrollment chain
                return responseFromUpstream;
        }
    }

    private PKIMessage processCertResponse(
            final PKIMessage incomingRequest,
            final int preprocessedRequestType,
            final PersistencyContext persistencyContext,
            final PKIMessage responseFromUpstream)
            throws BaseCmpException {
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
                    if (responseType == PKIBody.TYPE_CERT_REP || responseType == PKIBody.TYPE_KEY_UPDATE_REP) {
                        responseType = PKIBody.TYPE_KEY_UPDATE_REP;
                        responseTypeOk = true;
                    }
                    break;
                default:
                    throw new CmpProcessingException(
                            INTERFACE_NAME, PKIFailureInfo.systemFailure, "internal error in processCertResponse");
            }
            if (!responseTypeOk) {
                throw new CmpValidationException(
                        INTERFACE_NAME,
                        PKIFailureInfo.badMessageCheck,
                        "unexpected response to certificate request: " + MessageDumper.msgAsShortString(incomingRequest)
                                + "->" + MessageDumper.msgAsShortString(responseFromUpstream));
            }
            final CertRepMessage certRep =
                    (CertRepMessage) responseFromUpstream.getBody().getContent();

            final CertResponse certResponse = certRep.getResponse()[0];
            final int pkiStatus = certResponse.getStatus().getStatus().intValue();
            if (pkiStatus != PKIStatus.GRANTED && pkiStatus != PKIStatus.GRANTED_WITH_MODS) {
                // error in response
                return responseFromUpstream;
            }
            final CMPCertificate enrolledCertificate =
                    certResponse.getCertifiedKeyPair().getCertOrEncCert().getCertificate();
            final X509Certificate enrolledCertificateAsX509 = CertUtility.asX509Certificate(enrolledCertificate);
            final TrustCredentialAdapter enrollmentValidator = new TrustCredentialAdapter(
                    ConfigLogger.log(
                            INTERFACE_NAME,
                            "Configuration.getEnrollmentTrust",
                            config::getEnrollmentTrust,
                            persistencyContext.getCertProfile(),
                            responseType),
                    INTERFACE_NAME);

            // there is really a certificate and not only an error in the response
            // validate and fix certificate issuing chain
            final List<? extends X509Certificate> issuingChainAsX509 = enrollmentValidator.validateCertAgainstTrust(
                    enrolledCertificateAsX509,
                    ifNotNull(responseFromUpstream.getExtraCerts(), CertUtility::asX509Certificates));
            if (issuingChainAsX509 == null || issuingChainAsX509.isEmpty()) {
                throw new CmpValidationException(
                        INTERFACE_NAME,
                        PKIFailureInfo.signerNotTrusted,
                        "could not validate trust chain of issued certificate");
            }
            final List<CMPCertificate> issuingChain = issuingChainAsX509.stream()
                    .filter(x -> !x.equals(enrolledCertificateAsX509))
                    .map(wrap(x -> CMPCertificate.getInstance(x.getEncoded())))
                    .collect(Collectors.toList());
            persistencyContext.setIssuingChain(issuingChain);

            // update inventory
            final InventoryInterface inventory = ConfigLogger.logOptional(
                    INTERFACE_NAME,
                    "Configuration.getInventory",
                    config::getInventory,
                    persistencyContext.getCertProfile(),
                    responseType);
            if (inventory != null) {
                final byte[] encodedEnrolledCertificate = enrolledCertificate.getEncoded();
                if (!ConfigLogger.log(
                        INTERFACE_NAME,
                        "InventoryInterface.learnEnrollmentResult(byte[], byte[], String, String, String)",
                        () -> inventory.learnEnrollmentResult(
                                persistencyContext.getTransactionId(),
                                encodedEnrolledCertificate,
                                enrolledCertificateAsX509.getSerialNumber().toString(),
                                enrolledCertificateAsX509
                                        .getSubjectX500Principal()
                                        .toString(),
                                enrolledCertificateAsX509
                                        .getIssuerX500Principal()
                                        .toString()))) {
                    throw new CmpEnrollmentException(
                            incomingRequest.getBody().getType(),
                            INTERFACE_NAME,
                            PKIFailureInfo.systemFailure,
                            "enrolled certificate improperly processed by external inventory");
                }
            }

            // check for previous central key generation
            final PrivateKey newGeneratedPrivateKey = persistencyContext.getNewGeneratedPrivateKey();
            if (newGeneratedPrivateKey == null) {
                // no central key generation
                return responseFromUpstream;
            }

            // central key generation, respond the private key too
            final CkgContext ckgConfiguration = ConfigLogger.log(
                    INTERFACE_NAME,
                    "Configuration.getCkgConfiguration",
                    config::getCkgConfiguration,
                    persistencyContext.getCertProfile(),
                    responseType);
            if (ckgConfiguration == null) {
                throw new CmpEnrollmentException(
                        initialRequestType,
                        INTERFACE_NAME,
                        PKIFailureInfo.notAuthorized,
                        "no credentials for private key signing available");
            }

            final SignatureCredentialContext signingCredentials = ConfigLogger.log(
                    INTERFACE_NAME, "CkgContext.getSigningCredentials()", ckgConfiguration::getSigningCredentials);
            if (signingCredentials == null) {
                throw new CmpEnrollmentException(
                        initialRequestType,
                        INTERFACE_NAME,
                        PKIFailureInfo.notAuthorized,
                        "central key generation configuration is missing signature credentials");
            }
            final DataSigner keySigner =
                    new DataSigner(new SignatureBasedProtection(signingCredentials, INTERFACE_NAME));

            final CmsEncryptorBase keyEncryptor =
                    buildEncryptor(incomingRequest, ckgConfiguration, initialRequestType, INTERFACE_NAME);

            final PKIBody responseBodyWithPrivateKey = PkiMessageGenerator.generateIpCpKupBody(
                    responseType, enrolledCertificate, newGeneratedPrivateKey, keyEncryptor, keySigner);
            return PkiMessageGenerator.generateUnprotectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(PKIHeader.CMP_2021, responseFromUpstream),
                    responseBodyWithPrivateKey);
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            LOGGER.warn("could not properly process certificate response", ex);
            throw new CmpProcessingException(
                    INTERFACE_NAME,
                    PKIFailureInfo.wrongAuthority,
                    "could not properly process certificate response: " + ex);
        }
    }
}
