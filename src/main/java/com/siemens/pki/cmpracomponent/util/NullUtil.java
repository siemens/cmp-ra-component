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

    private NullUtil() {}

    public static <T> T computeDefaultIfNull(final T value, final Supplier<T> defaultSupplier) {
        return value != null ? value : defaultSupplier.get();
    }

    public static <T> T defaultIfNull(final T value, final T defaultValue) {
        return value != null ? value : defaultValue;
    }

    public static <T, R, E extends Exception> T ifNotNull(final R value, final ExFunction<R, T, E> function) throws E {
        try {
            return value == null ? null : function.apply(value);
        } catch (final NullPointerException npe) {
            return null;
        }
    }

    public interface ExFunction<T, R, E extends Exception> {
        R apply(T arg) throws E;
    }
}
