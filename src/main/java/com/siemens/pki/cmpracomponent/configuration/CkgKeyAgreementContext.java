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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;

/**
 * an instance of this interface provides all attributes required to implement
 * key agreement in context of central key generation
 *
 */
public interface CkgKeyAgreementContext {
    /**
     * specifies the algorithm used for key agreement, see
     * <a href=
     * "https://tools.ietf.org/wg/lamps/draft-ietf-lamps-cmp-algorithms">
     * Certificate Management Protocol (CMP) Algorithms </a>,
     * section "Key Agreement Algorithms"
     *
     * @return name or OID of an key agreement algorithm
     */
    default String getKeyAgreementAlg() {
        return SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme.getId();
    }

    /**
     * specifies the algorithm used for key encryption, see
     * <a href=
     * "https://tools.ietf.org/wg/lamps/draft-ietf-lamps-cmp-algorithms">
     * Certificate Management Protocol (CMP) Algorithms </a>, section "Key
     * Management Algorithms"
     *
     * @return name or OID of an key encryption algorithm
     */
    default String getKeyEncryptionAlg() {
        return CMSAlgorithm.AES128_WRAP.getId();
    }

    /**
     * specifies the private key used for key agreement
     *
     * @return the private key used for key agreement
     */
    PrivateKey getOwnPrivateKey();

    /**
     * specifies the public key related to the {@link PrivateKey} returned by
     * {@link CkgKeyAgreementContext#getOwnPrivateKey()}
     *
     * @return the related public key
     */
    PublicKey getOwnPublicKey();

    /**
     * specifies the intended recipient by its certificate
     *
     * @param protectingCertificate
     *            protecting certificate of request
     *
     * @return the certificate of the recipient
     */
    default X509Certificate getRecipient(
            final X509Certificate protectingCertificate) {
        return protectingCertificate;
    }
}
