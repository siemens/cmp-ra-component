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

import org.bouncycastle.cms.CMSAlgorithm;

/**
 * base interface on central key generation configuration
 */
public interface CkgContext {

    /**
     * provide content encryption algorithm to build CMS EnvelopedData
     *
     * @return content encryption algorithm
     */
    default String getContentEncryptionAlg() {
        return CMSAlgorithm.AES128_CBC.getId();
    }

    /**
     * get a context to support key agreement in context of central key generation
     *
     * @return a key agreement context
     */
    CkgKeyAgreementContext getKeyAgreementContext();

    /**
     * get a context to support key transport in context of central key generation
     *
     * @return a key transport context
     */
    CkgKeyTransportContext getKeyTransportContext();

    /**
     * get a context to support password-based key management technique for key
     * encryption
     *
     * @return a password context
     */
    CkgPasswordContext getPasswordContext();

    /**
     * Provide credentials to sign the central generated private key. This shall be
     * done also for the CkgPasswordContext instance.
     *
     * @return credentials to sign the central generated private key
     */
    SignatureCredentialContext getSigningCredentials();
}
