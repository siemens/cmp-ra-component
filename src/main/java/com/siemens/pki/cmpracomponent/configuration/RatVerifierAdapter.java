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
package com.siemens.pki.cmpracomponent.configuration;

import com.siemens.pki.verifieradapter.asn1.AttestationResult;
import com.siemens.pki.verifieradapter.asn1.EvidenceStatement;
import java.math.BigInteger;

/**
 * adapter to remote attestation verfier
 */
public interface RatVerifierAdapter {

    /**
     * turn evidence into verification result
     * @param transactionId current CMP transactionId, used to map related calls to getFreshRatNonce and processRatVerification
     * @param evidence evidence provided by EE as DER encoded {@link EvidenceStatement}
     * @return verification result as DER  encoded {@link AttestationResult}
     */
    byte[] processRatVerification(byte[] transactionId, byte[] evidence);

    interface NonceResponseRet {

        /**
         * retuns the nonce of length len provided by the Verifier indicated with hint
         * @return nonce
         */
        byte[] getNonce();

        /**
         * indicates how long in seconds the Verifier considers the nonce valid
         * @return time in seconds or <code>null</code>
         */
        default Integer getExpiry() {
            return null;
        }

        /**
         * indicates which Verifier to request a nonce from
         * @return hint or <code>null</code>
         */
        default String getHint() {
            return null;
        }

        /**
         * indicates which Evidence type to request a nonce for
         * @return OID or <code>null</code>
         */
        default String getType() {
            return null;
        }

        /**
         * Siemens proprietary extension to carry additional data
         * @return additional data or <code>null</code>
         */
        default byte[] getVendorextension() {
            return null;
        }
    }

    /**
     * Generate nonce
     * @param transactionId current CMP transactionId, used to map related calls to getFreshRatNonce and processRatVerification
     * @param len the required length of the requested nonce, maybe <code>null</code>
     * @param type indicates which Evidence type to request a nonce for, OID as string or <code>null</code>
     * @param hint indicates which Verifier to request a nonce from, maybe <code>null</code>
     * @param vendorextension additional Siemens proprietary data, maybe <code>null</code>
     * @param encodedNonceRequest encoded NonceRequest containing len, type and hint
     * @return fresh BER encoded NonceResponse
     */
    NonceResponseRet generateNonce(
            byte[] transactionId,
            BigInteger len,
            String type,
            String hint,
            byte[] vendorextension,
            byte[] encodedNonceRequest);
}
