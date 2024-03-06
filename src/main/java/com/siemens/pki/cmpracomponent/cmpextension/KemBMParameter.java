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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *  KemBMParameter ::= SEQUENCE {
 *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
 *      kemContext   [0] OCTET STRING OPTIONAL,
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
    private final ASN1OctetString kemContext;
    private final ASN1Integer len;

    private final AlgorithmIdentifier mac;

    public KemBMParameter(
            AlgorithmIdentifier kdf, ASN1OctetString kemContext, ASN1Integer len, AlgorithmIdentifier mac) {
        this.kdf = kdf;
        this.kemContext = kemContext;
        this.len = len;
        this.mac = mac;
    }

    public KemBMParameter(AlgorithmIdentifier kdf, byte[] kemContext, int len, AlgorithmIdentifier mac) {
        this(kdf, kemContext != null ? new DEROctetString(kemContext) : null, new ASN1Integer(len), mac);
    }

    private KemBMParameter(ASN1Sequence seq) {
        kdf = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        final ASN1Encodable optionalKemContext = seq.getObjectAt(1);
        if (optionalKemContext instanceof ASN1TaggedObject) {
            final ASN1TaggedObject taggedKemContext = (ASN1TaggedObject) optionalKemContext;
            if (taggedKemContext.getTagNo() != 0) {
                throw new IllegalArgumentException("kemContext must be tagged with [0]");
            }
            kemContext = ASN1OctetString.getInstance(taggedKemContext, true);
            len = ASN1Integer.getInstance(seq.getObjectAt(2));
            mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
        } else {
            kemContext = null;
            len = ASN1Integer.getInstance(seq.getObjectAt(1));
            mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        }
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }

    public AlgorithmIdentifier getKdf() {
        return kdf;
    }

    public ASN1OctetString getKemContext() {
        return kemContext;
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
        final ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(kdf);
        addOptional(v, 0, kemContext);
        v.add(len);
        v.add(mac);

        return new DERSequence(v);
    }
}
