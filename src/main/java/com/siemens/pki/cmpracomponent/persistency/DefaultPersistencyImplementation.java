/*
 *  Copyright (c) 2023 Siemens AG
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
package com.siemens.pki.cmpracomponent.persistency;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.configuration.PersistencyInterface;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a {@link Map} based default implementation of {@link PersistencyInterface}
 *
 */
public class DefaultPersistencyImplementation implements PersistencyInterface {

    class ValueType {
        byte[] message;
        Date expirationTime;

        ValueType(final byte[] message, final Date expirationTime) {
            this.message = message;
            this.expirationTime = expirationTime;
        }
    }

    // do housekeeping every minute
    private static final long HOUSEKEEPING_PERIOD = 60 * 60 * 1000L;

    private static DefaultPersistencyImplementation instance;

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultPersistencyImplementation.class);

    /**
     * get a default singleton instance
     * @return the singleton instance
     */
    public static synchronized PersistencyInterface getInstance() {
        if (instance == null) {
            instance = new DefaultPersistencyImplementation(HOUSEKEEPING_PERIOD);
        }
        return instance;
    }

    private final Timer houskeepingTimer = new Timer("PersistencyHouskeeping", true);

    private final byte[] aesKey = CertUtility.generateRandomBytes(16);

    private final Map<byte[], ValueType> persistencyMap =
            Collections.synchronizedSortedMap(new TreeMap<>(Arrays::compare));

    /**
     * ctor
     * @param housekeepingPeriod time in seconds between two checks for expired transactions
     */
    public DefaultPersistencyImplementation(final long housekeepingPeriod) {
        houskeepingTimer.schedule(
                new TimerTask() {

                    @Override
                    public void run() {
                        doHousekeeping();
                    }
                },
                0,
                housekeepingPeriod);
    }

    @Override
    public void clearLastSavedMessage(final byte[] transactionId) {
        persistencyMap.remove(transactionId);
    }

    private void doHousekeeping() {
        final Date now = new Date();
        for (final Iterator<Entry<byte[], ValueType>> it =
                        persistencyMap.entrySet().iterator();
                it.hasNext(); ) {
            final Entry<byte[], ValueType> currentEntry = it.next();
            if (now.after(currentEntry.getValue().expirationTime)) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("transaction {} expired", Arrays.toString(currentEntry.getKey()));
                }
                it.remove();
            }
        }
    }

    @Override
    public byte[] getAesKeyForKeyWrapping() {
        return aesKey;
    }

    @Override
    public byte[] getLastSavedMessage(final byte[] transactionId) {
        return ifNotNull(persistencyMap.get(transactionId), x -> x.message);
    }

    @Override
    public void saveLastMessage(final byte[] transactionId, final byte[] message, final Date expirationTime) {
        persistencyMap.put(transactionId, new ValueType(message, expirationTime));
    }
}
