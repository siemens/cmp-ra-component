package com.siemens.pki.cmpracomponent.remoteattestation;

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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *
 * EVIDENCE-STATEMENT ::= TYPE-IDENTIFIER
 *
 *   EvidenceStatementSet EVIDENCE-STATEMENT ::= {
 *      ... -- Empty for now --
 *   }
 *
 *   EvidenceStatement ::= SEQUENCE {
 *      type   EVIDENCE-STATEMENT.&id({EvidenceStatementSet}),
 *      stmt   EVIDENCE-STATEMENT.&Type({EvidenceStatementSet}{@type})
 *   }
 * </pre>
 */
public class EvidenceStatement extends ASN1Object {
    public static EvidenceStatement getInstance(Object o) {
        if (o instanceof EvidenceStatement) {
            return (EvidenceStatement) o;
        }

        if (o != null) {
            return new EvidenceStatement(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private final ASN1ObjectIdentifier type;

    private final ASN1Encodable stmt;

    public EvidenceStatement(ASN1ObjectIdentifier infoType) {
        this(infoType, null);
    }

    public EvidenceStatement(ASN1ObjectIdentifier type, ASN1Encodable stmt) {
        if (type == null) {
            throw new NullPointerException("'type' cannot be null");
        }

        this.type = type;
        this.stmt = stmt;
    }

    private EvidenceStatement(ASN1Sequence seq) {
        type = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1) {
            stmt = seq.getObjectAt(1);
        } else {
            stmt = null;
        }
    }

    public ASN1Encodable getStmt() {
        return stmt;
    }

    public ASN1ObjectIdentifier getType() {
        return type;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        final ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(type);

        if (stmt != null) {
            v.add(stmt);
        }
        return new DERSequence(v);
    }
}
