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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *  KemBMParameter ::= SEQUENCE {
 *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
 *      len              INTEGER (1..MAX), -- output length of the KDF
 *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
 *   }
 */
public class KemBMParameter extends ASN1Object {
    public static KemBMParameter getInstance(Object o) {
        if (o instanceof KemBMParameter) {
            return (KemBMParameter) o;
        }

        if (o != null) {
            return new KemBMParameter(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private final AlgorithmIdentifier kdf;
    private final ASN1Integer len;

    private final AlgorithmIdentifier mac;

    public KemBMParameter(AlgorithmIdentifier kdf, ASN1Integer len, AlgorithmIdentifier mac) {
        this.kdf = kdf;
        this.len = len;
        this.mac = mac;
    }

    public KemBMParameter(AlgorithmIdentifier kdf, int len, AlgorithmIdentifier mac) {
        this(kdf, new ASN1Integer(len), mac);
    }

    private KemBMParameter(ASN1Sequence seq) {
        kdf = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        len = ASN1Integer.getInstance(seq.getObjectAt(1));
        mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
    }

    public AlgorithmIdentifier getKdf() {
        return kdf;
    }

    public ASN1Integer getLen() {
        return len;
    }

    public AlgorithmIdentifier getMac() {
        return mac;
    }

    /**
     * <pre>
     *  KemBMParameter ::= SEQUENCE {
     *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
     *      len              INTEGER (1..MAX),
     *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *    }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(kdf);
        v.add(len);
        v.add(mac);

        return new DERSequence(v);
    }
}
