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
package com.siemens.pki.cmpracomponent.msgvalidation;

/** This exception is created if a CMP message validation failed. */
public class CmpValidationException extends BaseCmpException {

    private static final long serialVersionUID = 1L;

    /**
     * ctor
     *
     * @param interfaceName interface name used as prefix message text
     * @param failInfo CMP failInfo proposed for CMP error message
     * @param errorDetails description of some details related to the error
     */
    public CmpValidationException(final String interfaceName, final int failInfo, final String errorDetails) {
        super(interfaceName, failInfo, errorDetails, null);
    }
}
