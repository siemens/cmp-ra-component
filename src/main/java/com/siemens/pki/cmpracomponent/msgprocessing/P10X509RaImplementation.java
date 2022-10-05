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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContextManager;
import com.siemens.pki.cmpracomponent.util.CmpFuncEx;
import com.siemens.pki.cmpracomponent.util.MessageDumper;

/**
 * implementation of a RA composed from a {@link P10X509RaUpstream} and a
 * {@link RaDownstream}
 *
 */
public class P10X509RaImplementation implements Function<byte[], byte[]> {

    private static final Collection<Integer> supportedMessageTypesOnDownstream =
            new HashSet<>(Arrays.asList(PKIBody.TYPE_P10_CERT_REQ,
                    PKIBody.TYPE_CERT_CONFIRM));

    private static final Logger LOGGER =
            LoggerFactory.getLogger(P10X509RaImplementation.class);

    private static final String INTERFACE_NAME = "P10 X509 upstream exchange";

    private RaDownstream downstream;

    /**
     * @param config
     *            specific configuration
     * @param rawUpstreamExchange
     *            upstream interface function
     * @throws Exception
     *             in case of error
     * @see CmpRaComponent
     */
    public P10X509RaImplementation(final Configuration config,
            final BiFunction<byte[], String, byte[]> rawUpstreamExchange)
            throws Exception {
        final PersistencyContextManager persistencyContextManager =
                new PersistencyContextManager(config.getPersistency());
        CmpFuncEx<CertificationRequest, CMPCertificate> upstreamExchange = null;
        if (rawUpstreamExchange != null) {
            upstreamExchange =
                    (request, certProfile, bodyTypeOfFirstRequest) -> {
                        if (LOGGER.isTraceEnabled()) {
                            LOGGER.trace("REQUEST at upstream for "
                                    + certProfile + " >>>>>");
                            LOGGER.trace(MessageDumper.dumpAsn1Object(request));
                        }
                        try {
                            final byte[] rawResponse =
                                    rawUpstreamExchange.apply(ifNotNull(request,
                                            CertificationRequest::getEncoded),
                                            certProfile);
                            final CMPCertificate response = ifNotNull(
                                    rawResponse, CMPCertificate::getInstance);
                            if (LOGGER.isTraceEnabled()) {
                                LOGGER.trace("RESPONSE at upstream for "
                                        + certProfile + " <<<<");
                                LOGGER.trace(
                                        MessageDumper.dumpAsn1Object(response));
                            }
                            return response;
                        } catch (final Throwable th) {
                            throw new CmpProcessingException(INTERFACE_NAME,
                                    PKIFailureInfo.systemFailure,
                                    "exception at external upstream while processing request for "
                                            + certProfile,
                                    th);
                        }
                    };
        }
        final P10X509RaUpstream upstream =
                new P10X509RaUpstream(upstreamExchange);
        this.downstream = new RaDownstream(persistencyContextManager, config,
                upstream, supportedMessageTypesOnDownstream);
    }

    @Override
    public byte[] apply(final byte[] rawRequest) {
        try {
            final PKIMessage request = PKIMessage.getInstance(rawRequest);
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("REQUEST at downstream >>>>>");
                LOGGER.trace(MessageDumper.dumpPkiMessage(request));
            }
            final PKIMessage response = downstream.handleInputMessage(request);
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("RESPONSE at downstream <<<<");
                LOGGER.trace(MessageDumper.dumpPkiMessage(response));
            }
            return ifNotNull(response, PKIMessage::getEncoded);
        } catch (final Exception e) {
            LOGGER.error("exception on downstream", e);
            throw new RuntimeException(e);
        }
    }

}
