/*
 *  Copyright (c) 2024 Siemens AG
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
package com.siemens.pki.cmpracomponent.cryptoservices;

import com.siemens.pki.cmpracomponent.util.NullUtil.ExFunction;
import java.security.Provider;
import java.util.Arrays;
import java.util.Collection;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * a wrapper around various {@link Provider}s
 */
public class ProviderWrapper {

    private static final BouncyCastlePQCProvider BOUNCY_CASTLE_PQC_PROVIDER = new BouncyCastlePQCProvider();

    /**
     * get instance of BouncyCastlePQCProvider
     *
     * @return a BouncyCastlePQCProvider
     */
    public static BouncyCastlePQCProvider getBouncyCastlePqcProvider() {
        return BOUNCY_CASTLE_PQC_PROVIDER;
    }

    /**
     * get instance of BouncyCastleProvider
     *
     * @return a gBouncyCastleProvider
     */
    public static BouncyCastleProvider getBouncyCastleProvider() {
        return BOUNCY_CASTLE_PROVIDER;
    }

    /**
     * return supported providers
     *
     * @return supported providers
     */
    public static Collection<Provider> getSupportedProviders() {
        return Arrays.asList(SUPPORTED_PROVIDERS);
    }

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    private static final Provider[] SUPPORTED_PROVIDERS =
            new Provider[] {BOUNCY_CASTLE_PROVIDER, BOUNCY_CASTLE_PQC_PROVIDER};
    /**
     * try a given function with all known providers. Return on first {@link Provider} not throwing an exception.
     * @param <T> return type of function
     * @param <R> argument type of function
     * @param <E> excption thrown by the function
     * @param function function to try with
     * @return funtion result if provider supports function and argument
     * @throws E if last provider failed
     */
    @SuppressWarnings("unchecked")
    public static <T, R, E extends Exception> T tryWithAllProviders(final ExFunction<Provider, T, E> function)
            throws E {
        E lastException = null;
        for (Provider aktProvider : SUPPORTED_PROVIDERS) {
            try {
                return function.apply(aktProvider);
            } catch (Exception ex) {
                lastException = (E) ex;
            }
        }
        throw lastException;
    }

    // utility class
    private ProviderWrapper() {}
}
