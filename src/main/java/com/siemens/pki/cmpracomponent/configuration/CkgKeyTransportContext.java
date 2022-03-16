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
 * an instance of this interface provides all attributes required to implement
 * key transport in context of central key generation
 *
 */
public interface CkgKeyTransportContext extends CkgContext {
    /**
     * specifies the intended recipient by its certificate. The public key
     * in the certificate is used for encryption.
     *
     * @param protectingCertificate
     *            protecting certificate of request
     * @return the certificates of the recipient
     */
    default X509Certificate getRecipient(
            final X509Certificate protectingCertificate) {
        return protectingCertificate;
    }

}
