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

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.msggeneration.MsgOutputProtector;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.msgvalidation.InputValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageContext;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageHeaderValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.ProtectionValidator;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContextManager;
import com.siemens.pki.cmpracomponent.util.CmpFuncEx;
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * representation of an CMP upstream interface of a RA
 */
class CmpRaUpstream implements RaUpstream {

    private static final String INTERFACE_NAME = "CMP upstream";

    private static final String NESTED_INTERFACE_NAME = "nested " + INTERFACE_NAME;

    private static final Logger LOGGER = LoggerFactory.getLogger(CmpRaUpstream.class);

    private static final Collection<Integer> supportedMessageTypes = new HashSet<>(Arrays.asList(
            PKIBody.TYPE_INIT_REP,
            PKIBody.TYPE_CERT_REP,
            PKIBody.TYPE_KEY_UPDATE_REP,
            PKIBody.TYPE_POLL_REP,
            PKIBody.TYPE_CONFIRM,
            PKIBody.TYPE_REVOCATION_REP,
            PKIBody.TYPE_NESTED,
            PKIBody.TYPE_GEN_MSG,
            PKIBody.TYPE_GEN_REP,
            PKIBody.TYPE_ERROR));

    private final CmpFuncEx<PKIMessage, PKIMessage> upstreamMsgHandler;

    private final Configuration config;
    private final PersistencyContextManager persistencyContextManager;

    /**
     * @param persistencyContextManager persistency interface
     * @param config                    specific configuration
     * @param upstreamExchange          upstream function
     */
    CmpRaUpstream(
            final PersistencyContextManager persistencyContextManager,
            final Configuration config,
            final CmpFuncEx<PKIMessage, PKIMessage> upstreamExchange) {
        this.persistencyContextManager = persistencyContextManager;
        this.config = config;
        this.upstreamMsgHandler = upstreamExchange;
    }

    void gotResponseAtUpstream(final PKIMessage responseMessage) throws IOException, CmpProcessingException {
        final PersistencyContext persistencyContext = persistencyContextManager.loadPersistencyContext(
                responseMessage.getHeader().getTransactionID().getOctets());
        if (persistencyContext == null) {
            throw new IllegalStateException("no related request known for provided response");
        }
        persistencyContext.setPendingDelayedResponse(responseMessage);
        persistencyContext.flush();
    }

    @Override
    public PKIMessage handleRequest(final PKIMessage in, final PersistencyContext persistencyContext)
            throws BaseCmpException {
        try {
            if (persistencyContext.isDelayedDeliveryInProgress()) {
                // delayed delivery in progress, handle some nessages locally
                switch (in.getBody().getType()) {
                    case PKIBody.TYPE_CERT_CONFIRM:
                        // handle cert confirm locally
                        return PkiMessageGenerator.generateUnprotectMessage(
                                PkiMessageGenerator.buildRespondingHeaderProvider(in),
                                PkiMessageGenerator.generatePkiConfirmBody());
                    case PKIBody.TYPE_POLL_REQ:
                        return handlePollReq(in, persistencyContext);
                    default:
                        throw new CmpProcessingException(
                                INTERFACE_NAME,
                                PKIFailureInfo.transactionIdInUse,
                                "transactionId was already useded for another request");
                }
            }

            PKIMessage sentMessage;
            final CmpMessageInterface upstreamConfiguration = ConfigLogger.log(
                    INTERFACE_NAME,
                    "Configuration.getUpstreamConfiguration",
                    config::getUpstreamConfiguration,
                    persistencyContext.getCertProfile(),
                    in.getBody().getType());
            if (in.getBody().getType() == PKIBody.TYPE_KEY_UPDATE_REQ) {
                // never re-protect a KUR
                sentMessage = in;
            } else {
                final MsgOutputProtector outputProtector = new MsgOutputProtector(
                        upstreamConfiguration, INTERFACE_NAME, new MessageContext(persistencyContext, null));
                sentMessage = outputProtector.protectOutgoingMessage(in, null);
            }
            final NestedEndpointContext nestedEndpointContext = ConfigLogger.logOptional(
                    INTERFACE_NAME,
                    "CmpMessageInterface.getNestedEndpointContext()",
                    upstreamConfiguration::getNestedEndpointContext);
            if (nestedEndpointContext != null) {
                final MsgOutputProtector nestedProtector =
                        new MsgOutputProtector(nestedEndpointContext, "NESTED CMP upstream", null);
                // wrap into nested message
                sentMessage = nestedProtector.protectOutgoingMessage(
                        new PKIMessage(
                                sentMessage.getHeader(),
                                new PKIBody(PKIBody.TYPE_NESTED, new PKIMessages(sentMessage)),
                                null),
                        null);
            }

            PKIMessage receivedMessage = upstreamMsgHandler.apply(
                    sentMessage, persistencyContext.getCertProfile(), persistencyContext.getRequestType());

            if (receivedMessage == null) {
                // start asynchronous transfer
                persistencyContext.setDelayedInitialRequest(in);
                return PkiMessageGenerator.generateUnprotectMessage(
                        PkiMessageGenerator.buildRespondingHeaderProvider(sentMessage),
                        PkiMessageGenerator.generateResponseBodyWithWaiting(sentMessage.getBody(), INTERFACE_NAME));
            }
            // synchronous transfer
            if (receivedMessage.getBody().getType() == PKIBody.TYPE_NESTED && nestedEndpointContext != null) {
                final MessageHeaderValidator nestedHeaderValidator = new MessageHeaderValidator(NESTED_INTERFACE_NAME);
                nestedHeaderValidator.validate(receivedMessage);
                final ProtectionValidator nestedProtectionValidator = new ProtectionValidator(
                        NESTED_INTERFACE_NAME,
                        ConfigLogger.logOptional(
                                NESTED_INTERFACE_NAME,
                                "NestedEndpointContext.getInputVerification()",
                                nestedEndpointContext::getInputVerification));
                nestedProtectionValidator.validate(receivedMessage);
                PKIHeader receivedMessageHeader = receivedMessage.getHeader();
                boolean isIncomingRecipientValid = ConfigLogger.log(
                        NESTED_INTERFACE_NAME,
                        "NestedEndpointContext.isIncomingRecipientValid()",
                        () -> nestedEndpointContext.isIncomingRecipientValid(
                                receivedMessageHeader.getRecipient().getName().toString()));
                if (isIncomingRecipientValid) {
                    // unpack 1st message
                    PKIMessage[] wrappedMessages =
                            ((PKIMessages) receivedMessage.getBody().getContent()).toPKIMessageArray();
                    if (wrappedMessages.length != 1) {
                        throw new CmpValidationException(
                                NESTED_INTERFACE_NAME,
                                0,
                                "unable to unpack NESTED messsage with " + wrappedMessages.length + " inner messages");
                    }
                    receivedMessage = wrappedMessages[0];
                } else {
                    return receivedMessage;
                }
            }
            final InputValidator inputValidator = new InputValidator(
                    INTERFACE_NAME,
                    config::getUpstreamConfiguration,
                    (x, y) -> false,
                    supportedMessageTypes,
                    persistencyContext);
            inputValidator.validate(receivedMessage);
            final PKIHeader inHeader = in.getHeader();
            final PKIHeader recHeader = receivedMessage.getHeader();
            if (!Objects.equals(inHeader.getTransactionID(), recHeader.getTransactionID())) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badMessageCheck, "transaction ID mismatch on upstream");
            }
            if (!Objects.equals(inHeader.getSenderNonce(), recHeader.getRecipNonce())) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
            }
            return receivedMessage;
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            LOGGER.error("exception at upstream interface", ex);
            throw new CmpProcessingException(INTERFACE_NAME, PKIFailureInfo.systemFailure, ex);
        }
    }

    private PKIMessage handlePollReq(final PKIMessage in, final PersistencyContext persistencyContext)
            throws BaseCmpException, GeneralSecurityException, IOException {
        final PKIMessage delayedResponse = persistencyContext.getPendingDelayedResponse();
        if (delayedResponse != null) {
            final InputValidator inputValidator = new InputValidator(
                    INTERFACE_NAME,
                    config::getUpstreamConfiguration,
                    (x, y) -> false,
                    supportedMessageTypes,
                    persistencyContext);
            inputValidator.validate(delayedResponse);
            final PKIHeader delayedRequestHeader =
                    persistencyContext.getDelayedInitialRequest().getHeader();
            final PKIHeader recHeader = delayedResponse.getHeader();
            if (!Objects.equals(delayedRequestHeader.getSenderNonce(), recHeader.getRecipNonce())) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
            }
            return delayedResponse;
        } else {
            return PkiMessageGenerator.generateUnprotectMessage(
                    PkiMessageGenerator.buildRespondingHeaderProvider(in),
                    PkiMessageGenerator.generatePollRep(ConfigLogger.log(
                            INTERFACE_NAME,
                            "Configuration.getRetryAfterTimeInSeconds",
                            config::getRetryAfterTimeInSeconds,
                            persistencyContext.getCertProfile(),
                            PKIBody.TYPE_POLL_REP)));
        }
    }
}
