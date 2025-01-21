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
package com.siemens.pki.verifieradapter.veraison.rest;

/**
 * hardcoded configuration parameter for veraison REST interface
 */
public class RestConfig {

    // utility class
    private RestConfig() {}

    /**
     * default REST API endpoint
     */
    public static final String DEFAULT_VERIFIER_BASE_PATH = "https://192.168.202.128:8080/challenge-response/v1";

    /**
     * HTTP conten typ to use
     */
    public static final String REQUEST_CONTENT_TYPE = "application/custom-plugin-evidence";

    /**
     * RAT nonce size
     */
    public static final int NONCE_SIZE = 32;
}
