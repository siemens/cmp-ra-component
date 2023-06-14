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
package com.siemens.pki.cmpracomponent.configuration;

import com.siemens.pki.cmpracomponent.util.NullUtil;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * support message handler supporting Get KEM ciphertext requests
 */
public interface GetKemCiphertextHandler extends SupportMessageHandlerInterface {

    /**
     * provide a public key used to build the shared secret key obtained by KEM
     * encapsulation
     *
     * @param trustedCertificate KEM certificate if provided by peer
     * @return a public key
     */
    default PublicKey getPubKey(X509Certificate trustedCertificate) {
        return NullUtil.ifNotNull(trustedCertificate, X509Certificate::getPublicKey);
    }
}
