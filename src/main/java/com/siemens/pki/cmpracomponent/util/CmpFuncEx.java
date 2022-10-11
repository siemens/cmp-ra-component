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

import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;

/**
 * a CMP related request/response function throwing {@link BaseCmpException}s
 *
 */
public interface CmpFuncEx<T, R> {

    /**
     * Applies this function to the given arguments.
     *
     * @param t
     *            the first function argument
     *
     * @param certProfile
     *            certificate profile extracted from
     *            the CMP request header generalInfo field or
     *            <code>null</code> if no certificate profile was found in
     *            the header.
     *
     * @param bodyTypeOfFirstRequest
     *            PKIBody type of the first request in this transaction.
     *            e.g. 0 for ir, 3 for cr, 7 for kur.
     *
     * @return the function result
     * @throws BaseCmpException
     *             in case of error
     */
    R apply(T t, String certProfile, int bodyTypeOfFirstRequest)
            throws BaseCmpException;
}
