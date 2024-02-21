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
package com.siemens.pki.cmpracomponent.remoteattestation.rest;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import org.openapitools.client.ApiClient;
import org.openapitools.client.api.DefaultApi;

/**
 * factory for {@link DefaultApi} REST clients
 */
public class RestApiFactory {

    private static final Map<String, DefaultApi> API_MAP = Collections.synchronizedMap(new WeakHashMap<>());

    private static DefaultApi createClient(String verifierBasePath) {
        final ApiClient defaultClient = org.openapitools.client.Configuration.getDefaultApiClient();
        // ugly hack to come around https://github.com/OpenAPITools/openapi-generator/issues/7059
        // by default "*/*" maps to "application/json" but veraison expects "application/psa-attestation-token" in POST
        defaultClient.setRequestInterceptor(builder -> builder.setHeader("Content-Type", "application/cert-mgmt.demo"));
        defaultClient.updateBaseUri(verifierBasePath);
        return new DefaultApi(defaultClient);
    }

    /**
     * create or reuse an API client
     *
     * @param path to reach the verifier
     * @return the API client
     */
    public static DefaultApi getCreateApiClient(String verifierBasePath) {
        return API_MAP.computeIfAbsent(verifierBasePath, RestApiFactory::createClient);
    }
}
