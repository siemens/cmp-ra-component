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

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContextManager;
import com.siemens.pki.cmpracomponent.util.CmpFuncEx;
import com.siemens.pki.cmpracomponent.util.FileTracer;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** implementation of a RA composed from a {@link CmpRaUpstream} and a {@link RaDownstream} */
public class CmpRaImplementation implements CmpRaInterface {

    private static final String DOWNSTREAM_INTERFACE_NAME = "RaDownstream";

    private static final String UPSTREAM_INTERFACE_NAME = "RaUpstream";

    private static final Logger LOGGER = LoggerFactory.getLogger(CmpRaImplementation.class);

    private static final Collection<Integer> supportedMessageTypesOnDownstream = new HashSet<>(Arrays.asList(
            PKIBody.TYPE_INIT_REQ,
            PKIBody.TYPE_CERT_REQ,
            PKIBody.TYPE_KEY_UPDATE_REQ,
            PKIBody.TYPE_P10_CERT_REQ,
            PKIBody.TYPE_POLL_REQ,
            PKIBody.TYPE_CERT_CONFIRM,
            PKIBody.TYPE_REVOCATION_REQ,
            PKIBody.TYPE_GEN_MSG));

    private static final String INTERFACE_NAME = "upstream exchange";
    private final CmpRaUpstream upstream;

    private final RaDownstream downstream;

    /**
     * ctor
     *
     * @param config specific configuration
     * @param rawUpstreamExchange upstream interface function
     * @throws Exception in case of error
     * @see CmpRaComponent
     */
    public CmpRaImplementation(final Configuration config, final UpstreamExchange rawUpstreamExchange)
            throws Exception {
        final PersistencyContextManager persistencyContextManager =
                new PersistencyContextManager(config.getPersistency());
        final CmpFuncEx<PKIMessage, PKIMessage> upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
            final String atUpstream = " at upstream interface " + "for first bodyType " + bodyTypeOfFirstRequest
                    + (certProfile == null ? "" : " and certProfile " + certProfile);
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("REQUEST" + atUpstream + " >>>>>");
                LOGGER.trace(MessageDumper.dumpPkiMessage(request));
            }
            FileTracer.logMessage(request, UPSTREAM_INTERFACE_NAME);
            if (rawUpstreamExchange == null) {
                throw new CmpProcessingException(
                        INTERFACE_NAME, PKIFailureInfo.systemUnavail, "no upstream configured" + atUpstream);
            }
            try {
                final byte[] rawResponse = rawUpstreamExchange.sendReceiveMessage(
                        ifNotNull(request, PKIMessage::getEncoded), certProfile, bodyTypeOfFirstRequest);
                final PKIMessage response = ifNotNull(rawResponse, PKIMessage::getInstance);
                if (LOGGER.isTraceEnabled()) {
                    LOGGER.trace("RESPONSE" + atUpstream + " <<<<");
                    LOGGER.trace(MessageDumper.dumpPkiMessage(response));
                }
                FileTracer.logMessage(response, UPSTREAM_INTERFACE_NAME);
                return response;
            } catch (final Throwable th) {
                throw new CmpProcessingException(
                        INTERFACE_NAME, PKIFailureInfo.systemFailure, "exception processing request" + atUpstream, th);
            }
        };
        this.upstream = new CmpRaUpstream(persistencyContextManager, config, upstreamExchange);
        this.downstream =
                new RaDownstream(persistencyContextManager, config, upstream, supportedMessageTypesOnDownstream);
    }

    @Override
    public void gotResponseAtUpstream(final byte[] rawResponse) throws Exception {
        final PKIMessage response = PKIMessage.getInstance(rawResponse);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("ASYNC RESPONSE at upstream <<<<");
            LOGGER.trace(MessageDumper.dumpPkiMessage(response));
        }
        FileTracer.logMessage(response, UPSTREAM_INTERFACE_NAME);
        upstream.gotResponseAtUpstream(response);
    }

    @Override
    public byte[] processRequest(final byte[] rawRequest) throws Exception {
        final PKIMessage request = PKIMessage.getInstance(rawRequest);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("REQUEST at downstream >>>>>");
            LOGGER.trace(MessageDumper.dumpPkiMessage(request));
        }
        FileTracer.logMessage(request, DOWNSTREAM_INTERFACE_NAME);
        final PKIMessage response = downstream.handleInputMessage(request);
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("RESPONSE at downstream <<<<");
            LOGGER.trace(MessageDumper.dumpPkiMessage(response));
        }
        FileTracer.logMessage(response, DOWNSTREAM_INTERFACE_NAME);
        return ifNotNull(response, PKIMessage::getEncoded);
    }
}
