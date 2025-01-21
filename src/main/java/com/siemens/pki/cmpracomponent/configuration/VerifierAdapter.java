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
package com.siemens.pki.cmpracomponent.configuration;

import org.openapitools.client.ApiException;

/**
 * adapter to verfier
 */
public interface VerifierAdapter {

    /**
     * turn evidence into verification result
     * @param transactionId current CMP transactionId, used to map related calls to getFreshRatNonce and processRatVerification
     * @param evidence eveidence provided by EE
     * @return verification result
     * @throws ApiException if API to Verifier fails
     * @throws InterruptedException it thread handling fails
     */
    String processRatVerification(byte[] transactionId, byte[] evidence) throws ApiException, InterruptedException;

    /**
     * create fres RAT nonce
     * @param transactionId current CMP transactionId, used to map related calls to getFreshRatNonce and processRatVerification
     * @return fresh RAT nonce from verifier
     * @throws ApiException if API to Verifier fails
     */
    byte[] getFreshRatNonce(byte[] transactionId) throws ApiException;
}
