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

/** representation of an CMP upstream interface of a RA */
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
     * @param config specific configuration
     * @param upstreamExchange upstream function
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
                return handleDelayedDelivery(in, persistencyContext);
            }

            PKIMessage sentMessage = prepareOutgoingMessage(in, persistencyContext);
            PKIMessage receivedMessage = upstreamMsgHandler.apply(
                    sentMessage, persistencyContext.getCertProfile(), persistencyContext.getRequestType());

            if (receivedMessage == null) {
                persistencyContext.setDelayedInitialRequest(in);
                return PkiMessageGenerator.generateUnprotectMessage(
                        PkiMessageGenerator.buildRespondingHeaderProvider(sentMessage),
                        PkiMessageGenerator.generateResponseBodyWithWaiting(sentMessage.getBody(), INTERFACE_NAME));
            }

            receivedMessage = handleNestedMessage(receivedMessage, persistencyContext);
            validateResponse(in, receivedMessage, persistencyContext);

            return receivedMessage;
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception ex) {
            LOGGER.error("exception at upstream interface", ex);
            throw new CmpProcessingException(INTERFACE_NAME, PKIFailureInfo.systemFailure, ex);
        }
    }

    private PKIMessage handleDelayedDelivery(PKIMessage in, PersistencyContext ctx)
            throws BaseCmpException, GeneralSecurityException, IOException {
        switch (in.getBody().getType()) {
            case PKIBody.TYPE_CERT_CONFIRM:
                return PkiMessageGenerator.generateUnprotectMessage(
                        PkiMessageGenerator.buildRespondingHeaderProvider(in),
                        PkiMessageGenerator.generatePkiConfirmBody());
            case PKIBody.TYPE_POLL_REQ:
                return handlePollReq(in, ctx);
            default:
                throw new CmpProcessingException(
                        INTERFACE_NAME,
                        PKIFailureInfo.transactionIdInUse,
                        "transactionId was already used for another request");
        }
    }

    private PKIMessage prepareOutgoingMessage(PKIMessage in, PersistencyContext ctx)
            throws CmpProcessingException, GeneralSecurityException, IOException {
        final CmpMessageInterface upstream = ConfigLogger.log(
                INTERFACE_NAME,
                "Configuration.getUpstreamConfiguration",
                config::getUpstreamConfiguration,
                ctx.getCertProfile(),
                in.getBody().getType());

        PKIMessage msg = (in.getBody().getType() == PKIBody.TYPE_KEY_UPDATE_REQ)
                ? in
                : new MsgOutputProtector(upstream, INTERFACE_NAME, new MessageContext(ctx, null))
                        .protectOutgoingMessage(in, null);

        final NestedEndpointContext nestedCtx = ConfigLogger.logOptional(
                INTERFACE_NAME, "CmpMessageInterface.getNestedEndpointContext", upstream::getNestedEndpointContext);

        if (nestedCtx != null) {
            msg = new MsgOutputProtector(nestedCtx, "NESTED CMP upstream", null)
                    .protectOutgoingMessage(
                            new PKIMessage(
                                    msg.getHeader(), new PKIBody(PKIBody.TYPE_NESTED, new PKIMessages(msg)), null),
                            null);
        }

        return msg;
    }

    private PKIMessage handleNestedMessage(PKIMessage received, PersistencyContext ctx) throws BaseCmpException {
        final NestedEndpointContext nestedCtx = ConfigLogger.logOptional(
                INTERFACE_NAME,
                "CmpMessageInterface.getNestedEndpointContext",
                config.getUpstreamConfiguration(
                        ctx.getCertProfile(), received.getBody().getType())::getNestedEndpointContext);

        if (received.getBody().getType() != PKIBody.TYPE_NESTED || nestedCtx == null) {
            return received;
        }

        new MessageHeaderValidator(NESTED_INTERFACE_NAME).validate(received);
        new ProtectionValidator(
                        NESTED_INTERFACE_NAME,
                        ConfigLogger.logOptional(
                                NESTED_INTERFACE_NAME,
                                "NestedEndpointContext.getInputVerification",
                                nestedCtx::getInputVerification))
                .validate(received);

        boolean isValidRecipient = ConfigLogger.log(
                NESTED_INTERFACE_NAME,
                "NestedEndpointContext.isIncomingRecipientValid",
                () -> nestedCtx.isIncomingRecipientValid(
                        received.getHeader().getRecipient().getName().toString()));

        if (!isValidRecipient) return received;

        PKIMessage[] innerMessages = ((PKIMessages) received.getBody().getContent()).toPKIMessageArray();
        if (innerMessages.length != 1) {
            throw new CmpValidationException(
                    NESTED_INTERFACE_NAME,
                    0,
                    "unable to unpack NESTED message with " + innerMessages.length + " inner messages");
        }

        return innerMessages[0];
    }

    private void validateResponse(PKIMessage in, PKIMessage received, PersistencyContext ctx) throws BaseCmpException {
        new InputValidator(
                        INTERFACE_NAME, config::getUpstreamConfiguration, (x, y) -> false, supportedMessageTypes, ctx)
                .validate(received);

        if (!Objects.equals(
                in.getHeader().getTransactionID(), received.getHeader().getTransactionID())) {
            throw new CmpValidationException(
                    INTERFACE_NAME, PKIFailureInfo.badMessageCheck, "transaction ID mismatch on upstream");
        }

        if (!Objects.equals(
                in.getHeader().getSenderNonce(), received.getHeader().getRecipNonce())) {
            throw new CmpValidationException(
                    INTERFACE_NAME, PKIFailureInfo.badRecipientNonce, "nonce mismatch on upstream");
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
