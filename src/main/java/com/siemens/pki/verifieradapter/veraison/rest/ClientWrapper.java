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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.siemens.pki.cmpracomponent.configuration.VerifierAdapter;
import java.net.Socket;
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.openapitools.client.ApiClient;
import org.openapitools.client.ApiException;
import org.openapitools.client.ApiResponse;
import org.openapitools.client.api.DefaultApi;
import org.openapitools.client.model.ChallengeResponseSession;
import org.openapitools.client.model.ChallengeResponseSession.StatusEnum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * encapsulates an veraison REST client
 */
public class ClientWrapper implements VerifierAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientWrapper.class);

    private final String verifierBasePath;

    private final DefaultApi wrappedDefaultApi;

    private final Map<byte[], String> sessionMap =
            Collections.synchronizedMap(new TreeMap<>((x, y) -> Arrays.compare(x, y)));

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

    /**
     * ctor
     * @param ratVerifierBasePath the REST base URI
     */
    public ClientWrapper(String ratVerifierBasePath) {
        this.verifierBasePath = ratVerifierBasePath;
        final ApiClient wrappedClient = org.openapitools.client.Configuration.getDefaultApiClient();
        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, TRUST_ALL_MANAGER, null);
            wrappedClient.setHttpClientBuilder(HttpClient.newBuilder().sslContext(sslContext));
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            LOGGER.error("init SSL", e);
        }
        // ugly hack to come around https://github.com/OpenAPITools/openapi-generator/issues/7059
        // by default "*/*" maps to "application/json" but veraison expects "application/custom-plugin-evidence" in POST
        wrappedClient.setRequestInterceptor(
                builder -> builder.setHeader("Content-Type", "application/custom-plugin-evidence"));
        wrappedClient.updateBaseUri(verifierBasePath);
        // ugly hack to come around
        // https://github.com/OpenAPITools/openapi-generator/issues/7059
        // by default "*/*" maps to "application/json" but veraison expects
        // "application/psa-attestation-token" in POST
        wrappedClient.setRequestInterceptor(
                builder -> builder.setHeader("Content-Type", RestConfig.REQUEST_CONTENT_TYPE));
        wrappedClient.updateBaseUri(ratVerifierBasePath);
        wrappedDefaultApi = new DefaultApi(wrappedClient);
    }

    @Override
    public byte[] getFreshRatNonce(byte[] transactionId) throws ApiException {
        final ApiResponse<ChallengeResponseSession> result =
                wrappedDefaultApi.newSessionPostWithHttpInfo(RestConfig.NONCE_SIZE, null);
        final int statusCode = result.getStatusCode();
        if (statusCode != 201 /* Created */) {
            throw new ApiException("RAT verifier at " + verifierBasePath + " returned HTTP status " + statusCode);
        }
        final ChallengeResponseSession data = result.getData();
        final StatusEnum status = data.getStatus();
        if (status != StatusEnum.WAITING) {
            throw new ApiException("RAT verifier at " + verifierBasePath + " returned status " + status);
        }
        final List<String> locations = result.getHeaders().get("Location");
        if (locations == null || locations.isEmpty()) {
            throw new ApiException("RAT verifier at " + verifierBasePath + " did not provide a new Session Location");
        }
        // Location: https://veraison.example/challenge-response/v1/session/1234567890
        final String[] splittedLocation = locations.get(0).split("/");
        final String sessionId = splittedLocation[splittedLocation.length - 1];
        sessionMap.put(transactionId, sessionId);
        return data.getNonce();
    }

    /**
     * Check if the attestation result is complete and positive.
     *
     * Ensure that the status is "complete" and that the evidence status is "affirming", any
     * deviation from that is considered a failure.
     *
     * @param jwt the JWT to check
     * @return true if the attestation result is positive, false otherwise
     */
    public boolean isAttestationResultPositive(String jwt) {
        if (jwt == null || jwt.isEmpty()) {
            return false;
        }

        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode root = mapper.readTree(jwt);

            String status = root.path("status").asText();
            if (status == null || !status.equals("complete")) {
                LOGGER.warn("Attestation status is not `complete`: " + status);
                return false;
            }

            // Examine the evidence to ensure the status is "affirming".
            // Check `result.submods.ATG_PLUGIN.ear.status` inside the JWT JSON structure. Beware that
            // `result` is a dot-separated string with 3 components encoded as base64, we look into the second one; and that
            // `ear.status` is an actual attribute name, not a nested structure.
            String attestationResultB64 = root.path("result").asText().split("\\.")[1];
            byte[] decodedPayload = Base64.getUrlDecoder().decode(attestationResultB64);
            JsonNode payloadNode = mapper.readTree(new String(decodedPayload));

            String earStatus = payloadNode.path("submods").path("ATG_PLUGIN").path("ear.status").asText();
            if (earStatus == null || !earStatus.equals("affirming")) {
                LOGGER.warn("Attestation result is not `affirming`: " + status);
                return false;
            }

            LOGGER.info("Attestation is `affirming`, verifier " +
                    payloadNode.path("ear.verifier-id").path("developer").asText("N/A"));
        } catch (JsonProcessingException e) {
            LOGGER.error("Failed to parse JWT: " + jwt, e);
            return false;
        }

        // TODO consider what other checks to perform
        // - nonce is correct
        // - the response did not expire
        return true;
    }

    @Override
    public String processRatVerification(byte[] transactionId, byte[] evidence)
            throws ApiException, InterruptedException {
        final String ratSessionId = sessionMap.get(transactionId);
        if (ratSessionId == null) {
            return null;
        }
        ApiResponse<ChallengeResponseSession> apiResponse =
                wrappedDefaultApi.sessionSessionIdGetWithHttpInfo(ratSessionId);
        int statusCode = apiResponse.getStatusCode();
        if (statusCode != 200) {
            throw new ApiException("RAT verifier at " + verifierBasePath + " returned HTTP status " + statusCode);
        }
        ChallengeResponseSession responseData = apiResponse.getData();
        final ChallengeResponseSession data = responseData;
        StatusEnum status = data.getStatus();
        if (status != StatusEnum.WAITING) {
            throw new ApiException("RAT verifier at " + verifierBasePath + "  not in status WAITING: " + status);
        }
        apiResponse = wrappedDefaultApi.sessionSessionIdPostWithHttpInfo(
                ratSessionId, Base64.getEncoder().encodeToString(evidence));
        for (; ; ) {
            statusCode = apiResponse.getStatusCode();
            switch (statusCode) {
                case 200: // The submission was successful and has been synchronously processed
                {
                    responseData = apiResponse.getData();
                    status = responseData.getStatus();
                    if (status != StatusEnum.COMPLETE) {
                        throw new ApiException(
                                "RAT verifier at " + verifierBasePath + " not in status COMPLETE: " + status);
                    }
                    final String resultJwt = responseData.getResult();
                    LOGGER.info("got attestation JWT:\n" + resultJwt);

                    if(!isAttestationResultPositive(resultJwt)) {
                        throw new ApiException("RAT verifier returned a negative attestation result");
                    }
                    return resultJwt;
                }
                case 202: // The client is supposed to poll the resource
                {
                    Thread.sleep(5000L);
                    apiResponse = wrappedDefaultApi.sessionSessionIdGetWithHttpInfo(ratSessionId);
                    continue;
                }
                default:
                    throw new ApiException(
                            "RAT verifier at " + verifierBasePath + " returned HTTP status " + statusCode);
            }
        }
    }
}
