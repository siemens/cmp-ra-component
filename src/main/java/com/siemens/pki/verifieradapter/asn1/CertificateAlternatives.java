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
package com.siemens.pki.verifieradapter.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * <pre>
 *
 * CertificateAlternatives ::=
 * CHOICE {
 *     cert Certificate,
 *     typedCert     [0] IMPLICIT TypedCert,
 *     typedFlatCert [1] IMPLICIT TypedFlatCert
 * }
 * </pre>
 */
public class CertificateAlternatives extends ASN1Object {

    public static CertificateAlternatives getInstance(Object o) {
        if (o instanceof CertificateAlternatives) {
            return (CertificateAlternatives) o;
        }
        if (ASN1Object.hasEncodedTagValue(o, 0)) {
            final ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(o);
            return new CertificateAlternatives(TypedCert.getInstance(tagged.getBaseObject()));
        }
        if (ASN1Object.hasEncodedTagValue(o, 1)) {
            final ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(o);
            return new CertificateAlternatives(TypedFlatCert.getInstance(tagged.getBaseObject()));
        }
        return new CertificateAlternatives(Certificate.getInstance(o));
    }

    private Certificate certificate;

    private TypedCert typedCert;

    private TypedFlatCert typedFlatCert;

    public CertificateAlternatives(Certificate certificate) {
        this.certificate = certificate;
    }

    public CertificateAlternatives(TypedCert typedCert) {
        this.typedCert = typedCert;
    }

    public CertificateAlternatives(TypedFlatCert typedFlatCert) {
        this.typedFlatCert = typedFlatCert;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public TypedCert getTypedCert() {
        return typedCert;
    }

    public TypedFlatCert getTypedFlatCert() {
        return typedFlatCert;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        if (certificate != null) {
            return certificate.toASN1Primitive();
        }
        if (typedCert != null) {
            return new DERTaggedObject(false, 0, typedCert);
        }
        if (typedFlatCert != null) {
            return new DERTaggedObject(false, 1, typedFlatCert);
        }
        return null;
    }
}
