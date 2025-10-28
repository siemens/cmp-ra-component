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
package com.siemens.pki.cmpracomponent.test.framework;

import java.security.SecureRandom;

/** */
public class TestUtils {

    public static final String PASSWORD = "Password";
    public static final char[] PASSWORD_AS_CHAR_ARRAY = PASSWORD.toCharArray();

    public static final String WRONG_PASSWORD = "WrongPassword";
    public static final char[] WRONG_PASSWORD_AS_CHAR_ARRAY = WRONG_PASSWORD.toCharArray();
    static final SecureRandom RANDOM = new SecureRandom();

    // utility class, never create an instance
    private TestUtils() {}
}
