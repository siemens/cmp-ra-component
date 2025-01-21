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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * <pre>
 * EvidenceBundle ::= SEQUENCE
 * {
 *     evidence  SEQUENCE OF EvidenceStatement,
 *     certs SEQUENCE OF CertificateAlternatives OPTIONAL
 * }
 * </pre>
 */
public class EvidenceBundle extends ASN1Object {

    public static EvidenceBundle getInstance(Object o) {
        if (o instanceof PKIMessage) {
            return (EvidenceBundle) o;
        }
        if (o != null) {
            return new EvidenceBundle(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private final ASN1Sequence evidence;

    private final ASN1Sequence certs;

    private EvidenceBundle(ASN1Sequence seq) {
        evidence = ASN1Sequence.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            certs = ASN1Sequence.getInstance(seq.getObjectAt(1));
        } else {
            certs = null;
        }
    }

    public EvidenceBundle(EvidenceStatement[] evidence) {
        this(evidence, null);
    }

    public EvidenceBundle(EvidenceStatement[] evidence, CertificateAlternatives[] certs) {
        this.evidence = new DERSequence(evidence);
        if (certs != null) {
            this.certs = new DERSequence(certs);
        } else {
            this.certs = null;
        }
    }

    public ASN1Sequence getCerts() {
        return certs;
    }

    public ASN1Sequence getEvidence() {
        return evidence;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(evidence);
        if (certs != null) {
            v.add(certs);
        }
        return new DERSequence(v);
    }
}
