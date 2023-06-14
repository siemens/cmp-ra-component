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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * an instance implementing {@link CredentialContext} provides all
 * attributes needed for shared secret based CMP protection
 */
public interface KEMCredentialContext extends CredentialContext {

    /**
     * KDF used to generate the shared secret mac key.
     * @return KDF algorithm name, OID and optional parameters to use
     */
    default String getKdf() {
        return PKCSObjectIdentifiers.id_alg_hkdf_with_sha256.getId();
    }

    /**
     * specifies intended key length to be produced
     *
     * @return intended key length
     */
    default int getkeyLength() {
        return 4096;
    }

    /**
     * specifies the MAC algorithm to use and optional parameters to use. This
     * string may also include parameters not covered by the other already defined
     * methods of {@link SharedSecretCredentialContext}
     *
     * @return MAC algorithm name, OID and optional parameters to use
     */
    default String getMacAlgorithm() {
        return PKCSObjectIdentifiers.id_hmacWithSHA256.getId();
    }

    /**
     * provide a private key used to build the shared secret key obtained by KEM decapsulation
     * @return a private key
     */
    default PrivateKey getPrivkey() {
        return null;
    }

    /**
     * provide a certificate chain starting with the KEM end certificate and also
     * containing all required intermediate certificate usable for KEM protection,
     * authentication, signing or encryption
     *
     * @return a certificate chain starting with the end certificate
     */
    default List<X509Certificate> getCertificateChain() {
        return Collections.emptyList();
    }
}
