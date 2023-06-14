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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *    KemCiphertextInfo ::= SEQUENCE {
 *      kem              AlgorithmIdentifier{KEM-ALGORITHM, {...}},
 *      ct               OCTET STRING
 *    }
 */
public class KemCiphertextInfo extends ASN1Object {
    public static KemCiphertextInfo getInstance(Object o) {
        if (o instanceof KemCiphertextInfo) {
            return (KemCiphertextInfo) o;
        }

        if (o != null) {
            return new KemCiphertextInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private final AlgorithmIdentifier kem;
    private final ASN1OctetString ct;

    public KemCiphertextInfo(AlgorithmIdentifier kem, ASN1OctetString ct) {
        this.kem = kem;
        this.ct = ct;
    }

    private KemCiphertextInfo(ASN1Sequence seq) {
        kem = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        ct = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public ASN1OctetString getCt() {
        return ct;
    }

    public AlgorithmIdentifier getKem() {
        return kem;
    }

    /**
     * <pre>
     *    KemCiphertextInfo ::= SEQUENCE {
     *      kem              AlgorithmIdentifier{KEM-ALGORITHM, {...}},
     *      ct               OCTET STRING
     *    }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(kem);
        v.add(ct);

        return new DERSequence(v);
    }

    @Override
    public String toString() {
        return "KemCiphertextInfo [kem=" + kem.getAlgorithm() + ", \n\tct=" + ct + "]";
    }
}
