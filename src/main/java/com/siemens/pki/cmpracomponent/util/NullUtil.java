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
package com.siemens.pki.cmpracomponent.util;

import java.util.function.Supplier;

/**
 * utility functions to handle <code>null</code> values
 */
public class NullUtil {

    /**
     * function with one argument throwing an exception
     * @param <T> argument type
     * @param <R> result type
     * @param <E> exception type
     */
    public interface ExFunction<T, R, E extends Exception> {
        /**
         * execute function
         * @param arg function argument
         * @return result
         * @throws E in case of error
         */
        R apply(T arg) throws E;
    }

    /**
     * compute a default value if value is <code>null</code>
     * @param <T> value type
     * @param value value to check for <code>null</code>
     * @param defaultSupplier funtion to call if value is <code>null</code>
     * @return value or result of defaultSupplier
     */
    public static <T> T computeDefaultIfNull(final T value, final Supplier<T> defaultSupplier) {
        return value != null ? value : defaultSupplier.get();
    }

    /**
     * provide a default value if if value is <code>null</code>
     * @param <T> value type
     * @param value value to check for <code>null</code>
     * @param defaultValue value to use if provided value is <code>null</code>
     * @return value or defaultValue
     */
    public static <T> T defaultIfNull(final T value, final T defaultValue) {
        return value != null ? value : defaultValue;
    }

    /**
     * evaluate a function if a parameter is not <code>null</code>
     * @param <T> funtion result type
     * @param <R> value type
     * @param <E> exception thrown by function
     * @param value value to evaluate for <code>null</code>, function parameter
     * @param function function to evaluate
     * @return null or function result
     * @throws E if function throws an exception
     */
    public static <T, R, E extends Exception> T ifNotNull(final R value, final ExFunction<R, T, E> function) throws E {
        try {
            return value == null ? null : function.apply(value);
        } catch (final NullPointerException npe) {
            return null;
        }
    }

    // utility function
    private NullUtil() {}
}
