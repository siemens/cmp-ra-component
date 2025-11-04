/*
 *  Copyright (c) 2025 Siemens AG
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
package com.siemens.pki.cmpclientcomponent.main;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.msggeneration.HeaderProvider;
import com.siemens.pki.cmpracomponent.msggeneration.MsgOutputProtector;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageBodyValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageHeaderValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.ProtectionValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.ValidatorIF;
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import com.siemens.pki.cmpracomponent.util.FileTracer;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** low level client request functions */
class ClientRequestHandler {

    class ValidatorAndProtector {

        private final MsgOutputProtector outputProtection;

        private final ProtectionValidator protectionValidator;

        private final MessageHeaderValidator headerValidator;

        private final ValidatorIF<Boolean> bodyValidator;

        private final VerificationContext inputVerification;

        public ValidatorAndProtector(NestedEndpointContext nestedEndpoint)
                throws GeneralSecurityException, CmpProcessingException {
            headerValidator = new MessageHeaderValidator(NESTED_INTERFACE_NAME);
            outputProtection = new MsgOutputProtector(nestedEndpoint, NESTED_INTERFACE_NAME, null);
            this.inputVerification = ConfigLogger.logOptional(
                    NESTED_INTERFACE_NAME,
                    "NestedEndpointContext.getInputVerification()",
                    nestedEndpoint::getInputVerification);
            protectionValidator = new ProtectionValidator(
                    NESTED_INTERFACE_NAME,
                    ConfigLogger.logOptional(
                            NESTED_INTERFACE_NAME,
                            "NestedEndpointContext.getInputVerification()",
                            nestedEndpoint::getInputVerification));
            bodyValidator = new MessageBodyValidator(NESTED_INTERFACE_NAME, (x, y) -> false, null, certProfile);
        }

        private ValidatorAndProtector(String certProfile, final CmpMessageInterface upstreamConfiguration)
                throws GeneralSecurityException, CmpProcessingException {
            this.inputVerification = ConfigLogger.logOptional(
                    INTERFACE_NAME,
                    "CmpMessageInterface.getInputVerification()",
                    upstreamConfiguration::getInputVerification);
            headerValidator = new MessageHeaderValidator(INTERFACE_NAME);
            outputProtection = new MsgOutputProtector(upstreamConfiguration, INTERFACE_NAME, null);
            protectionValidator = new ProtectionValidator(INTERFACE_NAME, inputVerification);
            bodyValidator =
                    new MessageBodyValidator(INTERFACE_NAME, (x, y) -> false, upstreamConfiguration, certProfile);
        }

        public VerificationContext getInputVerification() {
            return inputVerification;
        }

        public MsgOutputProtector getOutputProtection() {
            return outputProtection;
        }

        private void validateResponse(final PKIMessage response) throws BaseCmpException {
            headerValidator.validate(response);
            protectionValidator.validate(response);

            bodyValidator.validate(response);
        }
    }

    private static final int DEFAULT_PVNO = PKIHeader.CMP_2000;

    private static final String INTERFACE_NAME = "ClientUpstream";

    public static final String NESTED_INTERFACE_NAME = "nested " + INTERFACE_NAME;

    /** The usual Logger. */
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientRequestHandler.class);

    private final ValidatorAndProtector validatorAndProtector;

    private final UpstreamExchange upstreamExchange;

    private final String certProfile;

    private final ValidatorAndProtector nestedValidatorAndProtector;

    /**
     * @param certProfile certificate profile to be used for enrollment. <code>null</code> if no certificate profile
     *     should be used.
     * @param upstreamExchange the {@link UpstreamExchange} interface implemented by the wrapping application.
     * @param upstreamConfiguration configuration for the upstream CMP interface towards the CA
     * @param clientContext client specific configuration
     * @throws Exception
     */
    ClientRequestHandler(
            String certProfile,
            final UpstreamExchange upstreamExchange,
            final CmpMessageInterface upstreamConfiguration,
            final ClientContext clientContext)
            throws Exception {
        this.upstreamExchange = upstreamExchange;
        this.certProfile = certProfile;
        validatorAndProtector = new ValidatorAndProtector(certProfile, upstreamConfiguration);
        nestedValidatorAndProtector = ifNotNull(
                ConfigLogger.logOptional(
                        INTERFACE_NAME,
                        "CmpMessageInterface.getNestedEndpointContext()",
                        upstreamConfiguration::getNestedEndpointContext),
                ValidatorAndProtector::new);
    }

    PKIMessage buildFurtherRequest(final PKIMessage formerResponse, final PKIBody requestBody) throws Exception {
        final PKIHeader formerResponseHeader = formerResponse.getHeader();
        return buildRequest(
                requestBody,
                formerResponseHeader.getTransactionID(),
                formerResponseHeader.getSenderNonce(),
                formerResponseHeader.getPvno().intValueExact(),
                false);
    }

    PKIMessage buildInitialRequest(final PKIBody requestBody, final boolean withImplicitConfirm) throws Exception {
        return buildInitialRequest(requestBody, withImplicitConfirm, DEFAULT_PVNO);
    }

    PKIMessage buildInitialRequest(final PKIBody requestBody, final boolean withImplicitConfirm, final int pvno)
            throws Exception {
        return buildRequest(
                requestBody, new DEROctetString(CertUtility.generateRandomBytes(16)), null, pvno, withImplicitConfirm);
    }

    private PKIMessage buildRequest(
            final PKIBody body,
            final ASN1OctetString transactionId,
            final ASN1OctetString recipNonce,
            final int pvno,
            final boolean withImplicitConfirm)
            throws Exception {
        final HeaderProvider headerProvider = new HeaderProvider() {
            final ASN1OctetString senderNonce = new DEROctetString(CertUtility.generateRandomBytes(16));

            @Override
            public InfoTypeAndValue[] getGeneralInfo() {
                if (certProfile == null && !withImplicitConfirm) {
                    return null;
                }
                final ArrayList<InfoTypeAndValue> genList = new ArrayList<>(2);
                if (certProfile != null) {
                    genList.add(new InfoTypeAndValue(
                            CMPObjectIdentifiers.id_it_certProfile, new DERSequence(new DERUTF8String(certProfile))));
                }
                if (withImplicitConfirm) {
                    genList.add(new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
                }
                return genList.toArray(new InfoTypeAndValue[0]);
            }

            @Override
            public int getPvno() {
                return pvno;
            }

            @Override
            public GeneralName getRecipient() {
                return null;
            }

            @Override
            public ASN1OctetString getRecipNonce() {
                return recipNonce;
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
                return transactionId;
            }
        };
        return validatorAndProtector.getOutputProtection().createOutgoingMessage(headerProvider, body);
    }

    public VerificationContext getInputVerification() {
        return validatorAndProtector.getInputVerification();
    }

    public MsgOutputProtector getOutputProtection() {
        return validatorAndProtector.getOutputProtection();
    }

    private boolean isWaitingIndication(final PKIBody responseBody) {
        try {
            switch (responseBody.getType()) {
                case PKIBody.TYPE_ERROR:
                    final ErrorMsgContent errorContent = (ErrorMsgContent) responseBody.getContent();
                    return errorContent.getPKIStatusInfo().getStatus().intValue() == PKIStatus.WAITING;
                case PKIBody.TYPE_INIT_REP:
                case PKIBody.TYPE_CERT_REP:
                case PKIBody.TYPE_KEY_UPDATE_REP:
                    final CertRepMessage certRepMessageContent = (CertRepMessage) responseBody.getContent();
                    return certRepMessageContent
                                    .getResponse()[0]
                                    .getStatus()
                                    .getStatus()
                                    .intValue()
                            == PKIStatus.WAITING;
                default:
                    return false;
            }
        } catch (final Exception ex) {
            // not decodable as waiting indication
            return false;
        }
    }

    PKIBody sendReceiveInitialBody(final PKIBody body) throws Exception {
        return sendReceiveValidateMessage(buildInitialRequest(body, false), body.getType())
                .getBody();
    }

    PKIBody sendReceiveInitialBody(final PKIBody body, final boolean withImplicitConfirm, final int firstRequestType)
            throws Exception {
        return sendReceiveValidateMessage(buildInitialRequest(body, withImplicitConfirm), firstRequestType)
                .getBody();
    }

    PKIMessage sendReceiveValidateMessage(PKIMessage request, final int firstRequestType) throws Exception {
        if (nestedValidatorAndProtector != null) {
            request = nestedValidatorAndProtector
                    .getOutputProtection()
                    .createOutgoingMessage(
                            PkiMessageGenerator.buildForwardingHeaderProvider(request),
                            new PKIBody(PKIBody.TYPE_NESTED, new PKIMessages(request)));
        }
        FileTracer.logMessage(request, INTERFACE_NAME);
        byte[] rawresponse = upstreamExchange.sendReceiveMessage(request.getEncoded(), certProfile, firstRequestType);
        if (rawresponse == null) {
            return null;
        }
        PKIMessage response = PKIMessage.getInstance(rawresponse);
        FileTracer.logMessage(response, INTERFACE_NAME);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("client received:\n" + MessageDumper.dumpPkiMessage(response));
        }
        if (response.getBody().getType() == PKIBody.TYPE_NESTED && nestedValidatorAndProtector != null) {
            nestedValidatorAndProtector.validateResponse(response);
            response = PKIMessages.getInstance(response.getBody().getContent()).toPKIMessageArray()[0];
        }
        validatorAndProtector.validateResponse(response);
        final PKIHeader requestHeader = request.getHeader();
        final ASN1OctetString firstRequestSenderNonce = requestHeader.getSenderNonce();
        final PKIHeader responseHeader = response.getHeader();
        if (!Objects.equals(firstRequestSenderNonce, responseHeader.getRecipNonce())) {
            throw new CmpValidationException(
                    INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
        }
        if (!Objects.equals(requestHeader.getTransactionID(), responseHeader.getTransactionID())) {
            throw new CmpValidationException(
                    INTERFACE_NAME, PKIFailureInfo.badMessageCheck, "transactionId mismatch on upstream");
        }
        if (!isWaitingIndication(response.getBody())) {
            // no delayed delivery
            return response;
        }
        for (; ; ) {
            // do polling
            final PKIMessage pollReq = buildFurtherRequest(response, PkiMessageGenerator.generatePollReq());
            FileTracer.logMessage(pollReq, INTERFACE_NAME);
            rawresponse = upstreamExchange.sendReceiveMessage(pollReq.getEncoded(), certProfile, firstRequestType);
            if (rawresponse == null) {
                return null;
            }
            response = PKIMessage.getInstance(rawresponse);
            FileTracer.logMessage(response, INTERFACE_NAME);
            validatorAndProtector.validateResponse(response);
            final PKIBody responseBody = response.getBody();
            final ASN1OctetString pollSenderNonce = pollReq.getHeader().getSenderNonce();
            final ASN1OctetString pollRecipNonce = response.getHeader().getRecipNonce();
            if (responseBody.getType() != PKIBody.TYPE_POLL_REP) {
                if (!Objects.equals(firstRequestSenderNonce, pollRecipNonce)
                        && !Objects.equals(pollSenderNonce, pollRecipNonce)) {
                    throw new CmpValidationException(
                            INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
                }
                return response;
            }
            if (!Objects.equals(pollSenderNonce, pollRecipNonce)) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
            }
            final int checkAfterTime = ((PollRepContent) responseBody.getContent())
                    .getCheckAfter(0)
                    .intPositiveValueExact();
            Thread.sleep(checkAfterTime * 1000L);
        }
    }
}
