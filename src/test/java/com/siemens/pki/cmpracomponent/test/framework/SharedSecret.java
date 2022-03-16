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

import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;

public class SharedSecret implements SharedSecretCredentialContext {

    private final byte[] sharedSecret;
    private final byte[] senderKid;
    private final byte[] salt;
    private final String prf;
    private final String macAlgorithm;
    private final int iterationCount;
    private final String style;

    public SharedSecret(final String style, final byte[] sharedSecret,
            final String macAlgorithm, final byte[] senderKid,
            final byte[] salt, final String prf, final int iterationCount) {
        this.style = style;
        this.sharedSecret = sharedSecret;
        this.macAlgorithm = macAlgorithm;
        this.senderKid = senderKid;
        this.salt = salt;
        this.prf = prf;
        this.iterationCount = iterationCount;
    }

    public SharedSecret(final String style, final String sharedSecret) {
        this(style, sharedSecret.getBytes(), "SHA256", "senderKid".getBytes(),
                CertUtility.generateRandomBytes(20), "SHA256", 10_000);
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
    }

    @Override
    public String getMacAlgorithm() {
        return macAlgorithm;
    }

    @Override
    public String getPasswordBasedMacAlgorithm() {
        return style;
    }

    @Override
    public String getPrf() {
        return prf;
    }

    @Override
    public byte[] getSalt() {
        return salt;
    }

    @Override
    public byte[] getSenderKID() {
        return senderKid;
    }

    @Override
    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}
