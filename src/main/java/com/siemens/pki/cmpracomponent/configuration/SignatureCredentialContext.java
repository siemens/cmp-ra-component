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

import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * an instance implementing {@link SignatureCredentialContext} provides all
 * attributes needed for signature based CMP protection, authentication, signing
 * or encryption
 */
public interface SignatureCredentialContext extends CredentialContext {

    /**
     * provide a certificate chain starting with the end certificate and also
     * containing all required intermediate certificate usable for CMP protection,
     * authentication, signing or encryption
     *
     * @return a certificate chain starting with the end certificate
     */
    List<X509Certificate> getCertificateChain();

    /**
     * provide the private key for the end certificate given in
     * {@link #getPrivateKey()}
     *
     * @return private key for first certificate returned by
     *         {@link #getCertificateChain()}
     */
    PrivateKey getPrivateKey();

    /**
     * provide name or OID of signature algorithm, see <a
     * href=https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#signature-algorithms>Signature
     * Algorithms</a>
     *
     * @return name or OID of signature algorithm as string. Name or OID specifies
     *         an asymmetric signature algorithm in conjunction with any needed
     *         digest algorithm.
     */
    default String getSignatureAlgorithmName() {
        return AlgorithmHelper.getSigningAlgNameFromKey(getPrivateKey());
    }
}
