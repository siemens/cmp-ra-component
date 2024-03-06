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
package com.siemens.pki.cmpracomponent.cmpextension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIFreeText;

/*
  KemOtherInfo ::= SEQUENCE {
     staticString     PKIFreeText,
     -- MUST be "CMP-KEM"
     transactionID    OCTET STRING,
     -- MUST contain the values from the message previously received
     -- containing the ciphertext (ct) in KemCiphertextInfo
     kemContext   [0] OCTET STRING OPTIONAL
     -- MAY contain additional algorithm specific context information
   }
*/

public class KemOtherInfo extends ASN1Object {

    private static final PKIFreeText DEFAULT_staticString = new PKIFreeText("CMP-KEM");

    public static KemOtherInfo getInstance(Object o) {
        if (o instanceof KemOtherInfo) {
            return (KemOtherInfo) o;
        }

        if (o != null) {
            return new KemOtherInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private final PKIFreeText staticString;
    private final ASN1OctetString transactionID;
    private final ASN1OctetString kemContext;

    public KemOtherInfo(ASN1OctetString transactionID, ASN1OctetString kemContext) {
        this.staticString = DEFAULT_staticString;
        this.transactionID = transactionID;
        this.kemContext = kemContext;
    }

    private KemOtherInfo(ASN1Sequence seq) {

        staticString = PKIFreeText.getInstance(seq.getObjectAt(0));
        transactionID = ASN1OctetString.getInstance(seq.getObjectAt(1));
        if (seq.size() > 2) {
            final ASN1Encodable optionalKemContext = seq.getObjectAt(2);
            if (optionalKemContext instanceof ASN1TaggedObject) {
                final ASN1TaggedObject taggedKemContext = (ASN1TaggedObject) optionalKemContext;
                if (taggedKemContext.getTagNo() == 0) {
                    kemContext = ASN1OctetString.getInstance(taggedKemContext, true);
                    return;
                }
            }
            throw new IllegalArgumentException("kemContext must be tagged with [0]");
        }
        kemContext = null;
    }

    public KemOtherInfo(byte[] transactionID, byte[] kemContext) {
        this.staticString = DEFAULT_staticString;
        this.transactionID = new BEROctetString(transactionID);
        this.kemContext = kemContext != null ? new BEROctetString(kemContext) : null;
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

    public ASN1OctetString getKemContext() {
        return kemContext;
    }

    public ASN1OctetString getTransactionID() {
        return transactionID;
    }

    /**
     * <pre>
     * KemOtherInfo ::= SEQUENCE {
     *   staticString      PKIFreeText,
     *   transactionID [0] OCTET STRING     OPTIONAL,
     *   senderNonce   [1] OCTET STRING     OPTIONAL,
     *   recipNonce    [2] OCTET STRING     OPTIONAL,
     *   len               INTEGER (1..MAX),
     *   mac               AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *   ct                OCTET STRING
     * }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(7);

        v.add(staticString);
        v.add(transactionID);
        addOptional(v, 0, kemContext);
        return new DERSequence(v);
    }

    @Override
    public String toString() {
        return "KemOtherInfo [staticString=" + staticString + ", transactionID=" + transactionID + ", kemContext="
                + kemContext + "]";
    }
}
