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
package com.siemens.pki.verifieradapter.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

/**
 *
 * {@code
 * EvidenceBundle ::= SEQUENCE {
 * evidences SEQUENCE SIZE (1..MAX) OF EvidenceStatement,
 * certs SEQUENCE SIZE (1..MAX) OF LimitedCertChoices OPTIONAL
 * }
 * }
 */
public class EvidenceBundle extends ASN1Object {

    private final ASN1EncodableVector evidences;
    private final ASN1EncodableVector certs;

    private EvidenceBundle(ASN1Sequence sequence) {
        evidences = new ASN1EncodableVector();
        evidences.addAll(ASN1Sequence.getInstance(sequence.getObjectAt(0)).toArray());
        if (sequence.size() > 1) {
            certs = new ASN1EncodableVector();
            certs.addAll(ASN1Sequence.getInstance(sequence.getObjectAt(1)).toArray());
        } else {
            certs = null;
        }
    }

    public EvidenceBundle(EvidenceStatement[] evidences, Certificate[] certs) {
        this.evidences = new ASN1EncodableVector();
        this.evidences.addAll(evidences);
        if (certs != null) {
            this.certs = new ASN1EncodableVector();
            this.certs.addAll(certs);
        } else {
            this.certs = null;
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector ret = new ASN1EncodableVector();
        ret.add(new DERSequence(evidences));
        if (certs != null && certs.size() > 0) {
            ret.add(new DERSequence(certs));
        }
        return new DERSequence(ret);
    }

    public static EvidenceBundle getInstance(Object o) {
        if (o instanceof EvidenceBundle) {
            return (EvidenceBundle) o;
        } else if (o != null) {
            return new EvidenceBundle(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public EvidenceStatement[] getEvidences() {
        EvidenceStatement[] ret = new EvidenceStatement[evidences.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = EvidenceStatement.getInstance(evidences.get(i));
        }
        return ret;
    }

    public Certificate[] getCerts() {
        if (certs == null) {
            return null;
        }
        Certificate[] ret = new Certificate[certs.size()];
        for (int i = 0; i < certs.size(); i++) {
            ret[i] = Certificate.getInstance(certs.get(i));
        }
        return ret;
    }
}
