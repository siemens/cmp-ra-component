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
package com.siemens.pki.cmpracomponent.configuration;

import java.security.cert.X509Certificate;

/**
 * support message handler supporting Get root CA certificate update genm
 * requests
 */
public interface GetRootCaCertificateUpdateHandler extends SupportMessageHandlerInterface {

    /**
     * response type for getRootCaCertificateUpdate
     */
    interface RootCaCertificateUpdateResponse {
        /**
         * return the new root CA certificate
         *
         * @return the new root CA certificate or <code>null</code> if the infoValue
         *         should be absent
         */
        X509Certificate getNewWithNew();

        /**
         * return a certificate containing the new public root CA key signed with the
         * old private root CA key
         *
         * @return a certificate containing the new public root CA key signed with the
         *         old private root CA key or <code>null</code> if absent
         */
        X509Certificate getNewWithOld();

        /**
         * return a certificate containing the old public root CA key signed with the
         * new private root CA key
         *
         * @return a certificate containing the old public root CA key signed with the
         *         new private root CA key or <code>null</code> if absent
         */
        X509Certificate getOldWithNew();
    }
    /**
     * handle an Get root CA certificate update GENM and return certificates to
     * build the related GENP response
     *
     * @param oldRootCaCertificate the old root CA certificate
     * @return certificates to be returned or <code>null</code> if the returned
     *         infoValue should be absent
     */
    RootCaCertificateUpdateResponse getRootCaCertificateUpdate(X509Certificate oldRootCaCertificate);
}
