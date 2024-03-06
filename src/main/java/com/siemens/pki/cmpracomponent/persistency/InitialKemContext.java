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
package com.siemens.pki.cmpracomponent.persistency;

import com.siemens.pki.cmpracomponent.cmpextension.KemCiphertextInfo;
import com.siemens.pki.cmpracomponent.cryptoservices.KemHandler;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.crypto.SecretWithEncapsulation;

public class InitialKemContext {

    private ASN1OctetString transactionID;

    private KemCiphertextInfo ciphertextInfo;

    private byte[] sharedSecret;

    public InitialKemContext() {}

    public InitialKemContext(ASN1OctetString transactionID, KemCiphertextInfo ciphertextInfo) {
        this.transactionID = transactionID;
        this.ciphertextInfo = ciphertextInfo;
    }

    public InitialKemContext(ASN1OctetString transactionID, PublicKey pubkey)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException,
                    CmpValidationException {
        if (pubkey == null) {
            throw new CmpValidationException(
                    "KEM context",
                    PKIFailureInfo.badMessageCheck,
                    "could not build ciphertextInfo, public KEM key not provided");
        }
        this.transactionID = transactionID;

        final KemHandler kemHandler = KemHandler.createKemHandler(pubkey.getAlgorithm());
        final SecretWithEncapsulation encapResult = kemHandler.encapsulate(pubkey);
        sharedSecret = encapResult.getSecret();
        ciphertextInfo = new KemCiphertextInfo(
                kemHandler.getAlgorithmIdentifier(), new BEROctetString(encapResult.getEncapsulation()));
    }

    public KemCiphertextInfo getCiphertextInfo() {
        return ciphertextInfo;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public byte[] getSharedSecret(PrivateKey key)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CmpValidationException {
        if (sharedSecret == null && key != null) {
            sharedSecret = KemHandler.createKemHandler(
                            ciphertextInfo.getKem().getAlgorithm().toString())
                    .decapsulate(ciphertextInfo.getCt().getOctets(), key);
        }
        if (sharedSecret == null) {
            throw new CmpValidationException(
                    "KEM context",
                    PKIFailureInfo.badMessageCheck,
                    "could not derive KEM shared secret, private KEM key not provided");
        }
        return sharedSecret;
    }

    public ASN1OctetString getTransactionID() {
        return transactionID;
    }

    public void setCiphertextInfo(KemCiphertextInfo ciphertextInfo) {
        this.ciphertextInfo = ciphertextInfo;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public void setTransactionID(ASN1OctetString transactionID) {
        this.transactionID = transactionID;
    }

    @Override
    public String toString() {
        return "InitialKemContext [transactionID=" + transactionID + ", ciphertextInfo=" + ciphertextInfo
                + ", sharedSecret=" + Arrays.toString(sharedSecret) + "]";
    }
}
