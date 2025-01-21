/*
 *  Copyright (c) 2023 Siemens AG
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

import com.siemens.pki.cmpracomponent.configuration.VerifierAdapter;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import org.openapitools.client.api.DefaultApi;

/**
 * factory for {@link DefaultApi} REST clients
 */
public class VerifierAdapterFactory {

    private static final Map<String, ClientWrapper> API_MAP = Collections.synchronizedMap(new WeakHashMap<>());

    private static ClientWrapper createVerifierClient(String verifierBasePath) {
        return new ClientWrapper(verifierBasePath);
    }
    /**
     * create or reuse an default API client wrapper
     *
     * @return the API client
     */
    public static VerifierAdapter getCreateVerifierClient() {
        return getCreateVerifierClient(RestConfig.DEFAULT_VERIFIER_BASE_PATH);
    }

    /**
     * create or reuse an API client wrapper
     *
     * @param verifierBasePath to reach the verifier
     * @return the API client
     */
    public static VerifierAdapter getCreateVerifierClient(String verifierBasePath) {
        return API_MAP.computeIfAbsent(verifierBasePath, path -> VerifierAdapterFactory.createVerifierClient(path));
    }

    /**
     * utility class
     */
    private VerifierAdapterFactory() {}
}
