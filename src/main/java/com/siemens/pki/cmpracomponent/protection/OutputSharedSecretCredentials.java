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
package com.siemens.pki.cmpracomponent.protection;

import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * an instance implementing {@link com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext} provides
 * all attributes needed for shared secret based CMP protection of outgoing messages
 */
public class OutputSharedSecretCredentials implements SharedSecretCredentialContext {

    final int iterationCount;
    final int keyLength;
    final String macAlgorithm;
    final String passwordBasedMacAlgorithm;
    final String prf;
    final byte[] salt;
    final byte[] senderKID;
    final byte[] sharedSecret;

    /**
     * Constructor for password-based MAC protection
     *
     * @param pbmParameter PBM parameter
     * @param senderKID sender key identifier
     * @param sharedSecret shared secret
     */
    public OutputSharedSecretCredentials(
            final PBMParameter pbmParameter, final byte[] senderKID, final byte[] sharedSecret) {
        this.iterationCount = pbmParameter.getIterationCount().getValue().intValue();
        this.macAlgorithm = pbmParameter.getMac().getAlgorithm().getId();
        this.passwordBasedMacAlgorithm = CMPObjectIdentifiers.passwordBasedMac.getId();
        this.prf = pbmParameter.getOwf().getAlgorithm().getId();
        this.salt = pbmParameter.getSalt().getOctets();
        this.senderKID = senderKID;
        this.sharedSecret = sharedSecret;

        this.keyLength = 0;
    }

    /**
     * Constructor for PMAC1 protection
     *
     * @param pbkdf2Params parameters for PBKDF2 key derivation function
     * @param macAlgorithm MAC algorithm
     * @param senderKID sender key identifer
     * @param sharedSecret shared secret
     */
    public OutputSharedSecretCredentials(
            PBKDF2Params pbkdf2Params, String macAlgorithm, byte[] senderKID, byte[] sharedSecret) {
        this.iterationCount = pbkdf2Params.getIterationCount().intValue();
        this.macAlgorithm = macAlgorithm;
        this.keyLength = pbkdf2Params.getKeyLength().intValue();
        this.passwordBasedMacAlgorithm = PKCSObjectIdentifiers.id_PBMAC1.getId();
        this.prf = pbkdf2Params.getPrf().getAlgorithm().getId();
        this.salt = pbkdf2Params.getSalt();
        this.senderKID = senderKID;
        this.sharedSecret = sharedSecret;
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
    }

    @Override
    public int getkeyLength() {
        return keyLength;
    }

    @Override
    public String getMacAlgorithm() {
        return macAlgorithm;
    }

    @Override
    public String getPasswordBasedMacAlgorithm() {
        return passwordBasedMacAlgorithm;
    }

    @Override
    public String getPrf() {
        return prf;
    }

    @Override
    public byte[] getSalt() {
        return salt;
    }

    @Override
    public byte[] getSenderKID() {
        return senderKID;
    }

    @Override
    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}
