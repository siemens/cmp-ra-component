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

import java.net.Socket;
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.openapitools.client.ApiClient;
import org.openapitools.client.api.DefaultApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * factory for {@link DefaultApi} REST clients
 */
public class RestApiFactory {

    private static final Map<String, DefaultApi> API_MAP = Collections.synchronizedMap(new WeakHashMap<>());

    private static final Logger LOGGER = LoggerFactory.getLogger(RestApiFactory.class);

    private static TrustManager[] TRUST_ALL_MANAGER = new TrustManager[] {
        new X509ExtendedTrustManager() {

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                    throws CertificateException {
                // TODO Auto-generated method stub

            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                    throws CertificateException {
                // TODO Auto-generated method stub

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                    throws CertificateException {
                // TODO Auto-generated method stub

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                    throws CertificateException {
                // TODO Auto-generated method stub

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
    };

    private static DefaultApi createClient(String verifierBasePath) {
        final ApiClient defaultClient = org.openapitools.client.Configuration.getDefaultApiClient();
        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, TRUST_ALL_MANAGER, null);
            defaultClient.setHttpClientBuilder(HttpClient.newBuilder().sslContext(sslContext));
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            LOGGER.error("init SSL", e);
        }
        // ugly hack to come around https://github.com/OpenAPITools/openapi-generator/issues/7059
        // by default "*/*" maps to "application/json" but veraison expects "application/custom-plugin-evidence" in POST
        defaultClient.setRequestInterceptor(
                builder -> builder.setHeader("Content-Type", "application/custom-plugin-evidence"));
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
