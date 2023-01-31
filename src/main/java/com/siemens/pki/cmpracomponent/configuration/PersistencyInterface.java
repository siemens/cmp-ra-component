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

import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * an implementation of the {@link PersistencyInterface} is used to persist the
 * state of all active transactions over RA component restarts and to share the
 * state of all active transactions between multiple RA instances in case of
 * load balancing or high availability scenarios
 */
public interface PersistencyInterface {

    /**
     * simple local implementation, if providing own implementations overwrite all
     * methods of {@link PersistencyInterface}
     */
    Map<byte[], byte[]> DEFAULT_PERSISTENCY_MAP = Collections.synchronizedSortedMap(new TreeMap<>(Arrays::compare));

    byte[] aesKey = CertUtility.generateRandomBytes(16);

    /**
     * clear and forget the last saved message related to a specific transaction.
     *
     * @param transactionId Id of a specific transaction
     */
    default void clearLastSavedMessage(final byte[] transactionId) {
        DEFAULT_PERSISTENCY_MAP.remove(transactionId);
    }

    /**
     * provide an AES key to wrap private keys in saved messages. The AES key needs
     * to be stable over the transactions lifetime.
     *
     * @return an AES key (16 bytes)
     */
    default byte[] getAesKeyForKeyWrapping() {
        return aesKey;
    }

    /**
     * get the last saved message related to a specific transaction.
     *
     * @param transactionId Id of a specific transaction
     * @return last saved message or <code>null</code> if no message was saved for
     *         this transaction
     */
    default byte[] getLastSavedMessage(final byte[] transactionId) {
        return DEFAULT_PERSISTENCY_MAP.get(transactionId);
    }

    /**
     * save the last PKI request or response related to a specific transaction. Any
     * previously saved message related to the same transaction is dropped.
     *
     * @param transactionId Id of a specific transaction
     * @param message       message to save
     */
    default void saveLastMessage(final byte[] transactionId, final byte[] message) {
        DEFAULT_PERSISTENCY_MAP.put(transactionId, message);
    }
}
