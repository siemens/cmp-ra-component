/*
 *  Copyright (c) 2024 Siemens AG
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
package com.siemens.pki.cmpclientcomponent.configuration;

import java.math.BigInteger;

/**
 * attestation specific configuration
 *
 */
public interface ClientAttestationContext {

    /**
     * obtain evidence statement from attestation
     * @param attestationNonce remote attestation nonce
     * @return remote attestation evidence statement
     */
    byte[] getEvidenceStatement(byte[] attestationNonce);

    /**
     * indicates which Verifier to request a nonce from
     * @return hint or <code>null</code>
     */
    default String getNonceRequestHint() {
        return null;
    }

    /**
     * indicates the required length of the requested nonce
     * @return length or <code>null</code>
     */
    default BigInteger getNonceRequestLen() {
        return null;
    }
    /**
     * indicates which Evidence type to request a nonce for
     * @return OID formatted string or <code>null</code>
     */
    default String getNonceRequestType() {
        return null;
    }
}
