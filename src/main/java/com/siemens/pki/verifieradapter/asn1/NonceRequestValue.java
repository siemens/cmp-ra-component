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

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * from https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/
 *
 * {@code
 * NonceRequestValue ::= SEQUENCE SIZE (1..MAX) OF NonceRequest
 * NonceRequest ::= SEQUENCE {
 * len    INTEGER OPTIONAL,
 * -- indicates the required length of the requested nonce
 * type   EVIDENCE-STATEMENT.&id({EvidenceStatementSet}) OPTIONAL,
 * -- indicates which Evidence type to request a nonce for
 * hint   UTF8String OPTIONAL
 * -- indicates which Verifier to request a nonce from
 * }
 * }
 */
public class NonceRequestValue extends ASN1Object {

    ASN1EncodableVector nonceRequests = new ASN1EncodableVector();

    public static class NonceRequest extends ASN1Object {
        public ASN1Integer getLen() {
            return len;
        }

        public ASN1ObjectIdentifier getType() {
            return type;
        }

        public ASN1UTF8String getHint() {
            return hint;
        }

        private ASN1Integer len = null;
        private ASN1ObjectIdentifier type = null;
        private ASN1UTF8String hint = null;

        public NonceRequest(ASN1Integer len, ASN1ObjectIdentifier type, ASN1UTF8String hint) {
            this.len = len;
            this.type = type;
            this.hint = hint;
        }

        public ASN1Primitive toASN1Primitive() {

            ASN1EncodableVector v = new ASN1EncodableVector(3);

            addOptional(v, len);
            addOptional(v, type);
            addOptional(v, hint);
            return new DERSequence(v);
        }

        public static NonceRequest getInstance(Object o) {
            if (o instanceof NonceRequest) {
                return (NonceRequest) o;
            } else if (o != null) {
                return new NonceRequest(ASN1Sequence.getInstance(o));
            }

            return null;
        }

        private NonceRequest(ASN1Sequence seq) {
            Enumeration<?> en = seq.getObjects();
            if (!en.hasMoreElements()) {
                return;
            }
            Object next = en.nextElement();
            if (next instanceof ASN1Integer) {
                len = ASN1Integer.getInstance(next);
                if (!en.hasMoreElements()) {
                    return;
                }
                next = en.nextElement();
            }
            if (next instanceof ASN1ObjectIdentifier) {
                type = ASN1ObjectIdentifier.getInstance(next);
                if (!en.hasMoreElements()) {
                    return;
                }
                next = en.nextElement();
            }
            if (next != null) {
                hint = ASN1UTF8String.getInstance(next);
            }
        }

        public NonceRequest(BigInteger nonceRequestLen, String nonceRequestType, String nonceRequestHint) {
            this(
                    nonceRequestLen != null ? new ASN1Integer(nonceRequestLen) : null,
                    nonceRequestType != null ? new ASN1ObjectIdentifier(nonceRequestType) : null,
                    nonceRequestHint != null ? new DERUTF8String(nonceRequestHint) : null);
        }

        private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
            if (obj != null) {
                v.add(obj);
            }
        }
    }

    public NonceRequestValue(NonceRequest[] requests) {
        nonceRequests.addAll(requests);
    }

    public NonceRequest[] getNonceRequests() {
        NonceRequest[] ret = new NonceRequest[nonceRequests.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = NonceRequest.getInstance(nonceRequests.get(i));
        }
        return ret;
    }

    public NonceRequestValue(ASN1Sequence instance) {
        for (int i = 0; i < instance.size(); i++) {
            nonceRequests.add(instance.getObjectAt(i));
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(nonceRequests);
    }

    public static NonceRequestValue getInstance(Object o) {
        if (o instanceof NonceRequestValue) {
            return (NonceRequestValue) o;
        } else if (o != null) {
            return new NonceRequestValue(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
