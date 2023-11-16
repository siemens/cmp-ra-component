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
/**
 *   TYPED-CERT ::= TYPE-IDENTIFIER
 *
 * CertType ::= TYPED-CERT.&id
 *
 * TypedCert ::= SEQUENCE {
 * certType     TYPED-CERT.&id({TypedCertSet}),
 * content     TYPED-CERT.&Type ({TypedCertSet}{@certType})
 * }
 */
package com.siemens.pki.cmpracomponent.remoteattestation;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 * TYPED-CERT ::= certType-IDENTIFIER
 *
 * CertType ::= TYPED-CERT.&id
 *
 * TypedCert ::= SEQUENCE {
 *               certType     TYPED-CERT.&id({TypedCertSet}),
 *               content     TYPED-CERT.&certType ({TypedCertSet}{@certType})
 *           }
 * </pre>
 */
public class TypedCert extends ASN1Object {

    public static TypedCert getInstance(Object o) {
        if (o instanceof TypedCert) {
            return (TypedCert) o;
        }

        if (o != null) {
            return new TypedCert(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private final ASN1ObjectIdentifier certType;

    private final ASN1Encodable content;

    public TypedCert(ASN1ObjectIdentifier infoType) {
        this(infoType, null);
    }

    public TypedCert(ASN1ObjectIdentifier certType, ASN1Encodable content) {
        if (certType == null) {
            throw new NullPointerException("'certType' cannot be null");
        }

        this.certType = certType;
        this.content = content;
    }

    private TypedCert(ASN1Sequence seq) {
        certType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1) {
            content = seq.getObjectAt(1);
        } else {
            content = null;
        }
    }

    public ASN1ObjectIdentifier getCertType() {
        return certType;
    }

    public ASN1Encodable getContent() {
        return content;
    }

    public ASN1Encodable getStmt() {
        return content;
    }

    public ASN1ObjectIdentifier getType() {
        return certType;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(certType);

        if (content != null) {
            v.add(content);
        }
        return new DERSequence(v);
    }
}
