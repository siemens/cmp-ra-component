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

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.cmpracomponent.util.NullUtil.ExFunction;
import java.util.Collection;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * validator for an incoming message
 */
public class InputValidator implements ValidatorIF<PersistencyContext> {

    private final Collection<Integer> supportedMessageTypes;
    private final String interfaceName;
    private final BiPredicate<String, Integer> isRaVerifiedAcceptable;
    private final BiFunction<String, Integer, CmpMessageInterface> config;
    private final ExFunction<byte[], PersistencyContext, Exception> persistencyContextCreator;

    /**
     * @param interfaceName             name of the attached interface used for
     *                                  logging
     * @param config                    specific configuration
     * @param isRaVerifiedAcceptable    should raVerified accepted for POPO?
     * @param supportedMessageTypes     acceptable CMP message types
     * @param persistencyContextCreator function to (re-)create a
     *                                  {@link PersistencyContext} out of a
     *                                  transaction id
     */
    public InputValidator(
            final String interfaceName,
            final BiFunction<String, Integer, CmpMessageInterface> config,
            final BiPredicate<String, Integer> isRaVerifiedAcceptable,
            final Collection<Integer> supportedMessageTypes,
            final ExFunction<byte[], PersistencyContext, Exception> persistencyContextCreator) {

        this.config = config;
        this.interfaceName = interfaceName;
        this.supportedMessageTypes = supportedMessageTypes;
        this.isRaVerifiedAcceptable = isRaVerifiedAcceptable;
        this.persistencyContextCreator = persistencyContextCreator;
    }

    /**
     * validate a message according to the given configuration and acceptable
     * message types
     *
     * @param in message to validate
     * @throws CmpProcessingException if validation failed
     */
    @Override
    public PersistencyContext validate(final PKIMessage in) throws BaseCmpException {
        if (!supportedMessageTypes.contains(in.getBody().getType())) {
            throw new CmpValidationException(
                    interfaceName,
                    PKIFailureInfo.badMessageCheck,
                    "message " + MessageDumper.msgTypeAsString(in) + " not supported ");
        }
        String certProfile = new MessageHeaderValidator(interfaceName).validate(in);
        try {
            final PersistencyContext persistencyContext = persistencyContextCreator.apply(
                    in.getHeader().getTransactionID().getOctets());
            persistencyContext.setCertProfile(certProfile);
            certProfile = persistencyContext.getCertProfile();
            final CmpMessageInterface cmpInterface =
                    config.apply(certProfile, in.getBody().getType());
            new MessageBodyValidator(interfaceName, isRaVerifiedAcceptable, cmpInterface, certProfile).validate(in);
            final ProtectionValidator protectionValidator =
                    new ProtectionValidator(interfaceName, cmpInterface.getInputVerification());
            protectionValidator.validate(in);
            return persistencyContext;
        } catch (final BaseCmpException ce) {
            throw ce;
        } catch (final Exception e) {
            throw new CmpProcessingException(interfaceName, e);
        }
    }
}
