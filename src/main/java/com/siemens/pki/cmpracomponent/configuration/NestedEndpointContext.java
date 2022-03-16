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
package com.siemens.pki.cmpracomponent.configuration;

/**
 *
 * provides all attributes needed to process
 * incoming and outgoing nested messages
 *
 */
public interface NestedEndpointContext {
    /**
     * configure trust for protection validation of incoming messages
     *
     * @return a trust configuration if the protection of incoming nested
     *         messages should be validated and nesting removed,
     *         <code>null</code> if all nested messages,
     *         regardless of their recipient,
     *         should be forwarded without validation
     */
    VerificationContext getInputVerification();

    /**
     * configure protection for outgoing messages
     *
     * @return a protection configuration, if outgoing message should be wrapped
     *         in nested messages or <code>null</code> if outgoing messaged
     *         shouldn't be wrapped.
     */
    CredentialContext getOutputCredentials();

    /**
     * configure handling of incoming nested messages per recipient.
     *
     * @param recipient
     *            the recipient in the PKI message header of the received nested
     *            message
     *
     * @return <code>true</code> if the RA is supposed to verify and unpack the
     *         nested message with the given recipient. Otherwise the RA will
     *         forward the nested message.
     */
    boolean isIncomingRecipientValid(String recipient);

}
