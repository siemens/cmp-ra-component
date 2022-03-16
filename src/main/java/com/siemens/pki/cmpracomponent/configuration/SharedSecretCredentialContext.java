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

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.PasswordRecipient;

import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;

/**
 * an instance implementing {@link SignatureCredentialContext} provides
 * all attributes needed for shared secret based CMP protection
 */
public interface SharedSecretCredentialContext extends CredentialContext {

    /**
     * specify iteration count to use
     *
     * @return input iteration count
     */
    default int getIterationCount() {
        return 10_000;
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
     * string may also include parameters not covered by the
     * other already defined methods of {@link SharedSecretCredentialContext}
     *
     * @return MAC algorithm name, OID and optional parameters to use
     *
     */
    default String getMacAlgorithm() {
        return PKCSObjectIdentifiers.id_hmacWithSHA256.getId();
    }

    /**
     * get the Password-Based MAC style if used for protection
     *
     * @return "PBMAC1", "PASSWORDBASEDMAC" or OID as string
     */
    default String getPasswordBasedMacAlgorithm() {
        return "PBMAC1";
    }

    /**
     * specifies the pseudo-random function or one way function to use
     *
     * @return a pseudo-random or owf function
     */
    default String getPrf() {
        return PasswordRecipient.PRF.HMacSHA256.getName();
    }

    /**
     * specify a salt to use
     *
     * @return input salt
     */
    default byte[] getSalt() {
        return CertUtility.generateRandomBytes(20);
    }

    /**
     * optionally provide a sender KID to be used for protected CMP message
     *
     * @return sender KID or <code>null</code>
     */
    default byte[] getSenderKID() {
        return null;
    }

    /**
     * provide a shared secret usable for MAC-based protection
     *
     * @return a shared secret
     */
    byte[] getSharedSecret();

}
