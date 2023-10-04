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
package com.siemens.pki.cmpracomponent.test.framework;

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;

public class PasswordValidationCredentials implements VerificationContext {
    private final byte[] sharedSecret;

    public PasswordValidationCredentials(final String sharedSecret) {
        this.sharedSecret = sharedSecret.getBytes();
    }

    public PasswordValidationCredentials(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    @Override
    public byte[] getSharedSecret(final byte[] senderKID) {
        return sharedSecret;
    }
}
