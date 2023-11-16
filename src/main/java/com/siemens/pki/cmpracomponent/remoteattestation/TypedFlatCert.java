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
package com.siemens.pki.cmpracomponent.remoteattestation;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * <pre>
 * TypedFlatCert ::= SEQUENCE {
 *     certType OBJECT IDENTIFIER,
 *     certBody OCTET STRING
 * }
 * </pre>
 */
public class TypedFlatCert extends ASN1Object {

    public static TypedFlatCert getInstance(Object o) {
        if (o instanceof PKIMessage) {
            return (TypedFlatCert) o;
        }
        if (o != null) {
            return new TypedFlatCert(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private final ASN1ObjectIdentifier certType;

    private final ASN1OctetString certBody;

    public TypedFlatCert(ASN1ObjectIdentifier certType, ASN1OctetString certBody) {
        this.certType = certType;
        this.certBody = certBody;
    }

    public TypedFlatCert(ASN1ObjectIdentifier certType, byte[] certBody) {
        this.certType = certType;
        this.certBody = new DEROctetString(certBody);
    }

    private TypedFlatCert(ASN1Sequence seq) {
        seq.getObjects();

        certType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        certBody = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public ASN1OctetString getCertBody() {
        return certBody;
    }

    public ASN1ObjectIdentifier getCertType() {
        return certType;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(certType);
        v.add(certBody);
        return new DERSequence(v);
    }
}
