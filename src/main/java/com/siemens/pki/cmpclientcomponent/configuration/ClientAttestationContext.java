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

import com.siemens.pki.verifieradapter.asn1.EvidenceBundle;
import com.siemens.pki.verifieradapter.asn1.EvidenceStatement;
import com.siemens.pki.verifieradapter.asn1.NonceResponseValue.NonceResponse;
import java.math.BigInteger;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * attestation specific configuration
 *
 */
public interface ClientAttestationContext {

    /**
     * obtain evidence statement from attestation
     * @param attestationNonce DER encoded {@link NonceResponse}
     * @return DER encoded {@link EvidenceStatement}
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

    /**
     * Siemens proprietary extension to carry additional data
     * @return additional data <code>null</code>
     */
    default byte[] getNonceRequestVendorextension() {
        return null;
    }
    /**
     * get certs to include in {@link EvidenceBundle}
     * @return certs
     */
    default Certificate[] getEvidenceBundleCerts() {
        return null;
    }
}
