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
package com.siemens.pki.cmpracomponent.configuration;

import com.siemens.pki.cmpracomponent.persistency.DefaultPersistencyImplementation;
import java.util.Date;

/**
 * an implementation of the {@link PersistencyInterface} is used to persist the state of all active transactions over RA
 * component restarts and to share the state of all active transactions between multiple RA instances in case of load
 * balancing or high availability scenarios
 */
public interface PersistencyInterface {

    /**
     * clear and forget the last saved message related to a specific transaction.
     *
     * @param transactionId Id of a specific transaction
     */
    default void clearLastSavedMessage(final byte[] transactionId) {
        DefaultPersistencyImplementation.getInstance().clearLastSavedMessage(transactionId);
    }

    /**
     * provide an AES key to wrap private keys in saved messages. The AES key needs to be stable over the transactions
     * lifetime.
     *
     * @return an AES key (16 bytes)
     */
    default byte[] getAesKeyForKeyWrapping() {
        return DefaultPersistencyImplementation.getInstance().getAesKeyForKeyWrapping();
    }

    /**
     * get the last saved message related to a specific transaction.
     *
     * @param transactionId Id of a specific transaction
     * @return last saved message or <code>null</code> if no message was saved for this transaction
     */
    default byte[] getLastSavedMessage(final byte[] transactionId) {
        return DefaultPersistencyImplementation.getInstance().getLastSavedMessage(transactionId);
    }

    /**
     * save the last PKI request or response related to a specific transaction. Any previously saved message related to
     * the same transaction is dropped.
     *
     * @param transactionId Id of a specific transaction
     * @param message message to save
     * @param expirationTime time when the save message should expire
     */
    default void saveLastMessage(final byte[] transactionId, final byte[] message, final Date expirationTime) {
        DefaultPersistencyImplementation.getInstance().saveLastMessage(transactionId, message, expirationTime);
    }
}
