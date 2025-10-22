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
 * this interface provides all configuration parameter required to configure an
 * CMP message interface
 */
public interface CmpMessageInterface {

    /**
     * the {@link ReprotectMode} controls how an outgoing message is protected
     */
    enum ReprotectMode {
        /**
         * the outgoing message will be reprotected in any case.
         */
        reprotect,
        /**
         * any protection is removed from the outgoing message
         */
        strip,
        /**
         * an existing protection of a forwarded message is preserved, if possible
         */
        keep
    }

    /**
     * configure trust for protection validation of incoming messages
     *
     * @return a trust configuration or <code>null</code> if protection validation
     *         is not needed
     */
    VerificationContext getInputVerification();

    /**
     * configuration if adding protection by use of nested messages should be
     * supported
     *
     * @return a NestedEndpointContext or <code>null</code> if no additional
     *         protection should be applied or validated
     */
    NestedEndpointContext getNestedEndpointContext();

    /**
     * configure protection for outgoing messages
     *
     * @return a protection configuration or <code>null</code> if no (re-)protection
     *         of outgoing messages is requested
     */
    CredentialContext getOutputCredentials();

    /**
     * allow to set new recipient for outgoing messages. The  recipient is only updated if no or
     * a new protection will be applied.
     * @return new recipient in RDN notation or <code>null</code> if already set recipient should remain.
     */
    default String getRecipient() {
        return null;
    }

    /**
     * provide configuration for protection mode of outgoing messages. Responses
     * to MAC-based requests at Downstream are always reprotected using the same
     * credentials if {@link CmpMessageInterface#isEnforceReprotectMode()}
     * returns <code>false</code>.
     *
     * @return protection mode
     */
    ReprotectMode getReprotectMode();

    /**
     * enforce protection mode of outgoing messages as given by
     * {@link #getReprotectMode()} even if the last incoming message was
     * MAC-based protected.
     * @return <code>true</code>, if reprotection can be enforced,
     * <code>false</code> if response to an MAC-based protected request should
     * be protected using the same credentials
     */
    default boolean isEnforceReprotectMode() {
        return false;
    }

    /**
     * If the method returns true, do not sent an extraCerts certificate twice in a
     * message flow related to a specific transactionID.
     *
     * @return <code>false</code> if always the whole protection chain and
     *         enrollment chain should be in the extraCerts.
     */
    boolean getSuppressRedundantExtraCerts();

    /**
     * determine whether certificate caching should be done
     *
     * @return <code>true</code> if all received extraCerts related to a specific
     *         transactionID should be cached and re-used if a message received
     *         later does not contain all certificates required to validate the
     *         protection.
     */
    boolean isCacheExtraCerts();

    /**
     * determine if messageTime of incoming message is acceptable
     *
     * @param deviation difference between message time in PKI message header and
     *                  local time in seconds
     * @return allowed time offset in seconds
     */
    boolean isMessageTimeDeviationAllowed(long deviation);
}
