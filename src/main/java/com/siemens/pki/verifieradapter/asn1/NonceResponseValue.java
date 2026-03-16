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

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * from https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/
 *
 * {@code
 * NonceResponseValue ::= SEQUENCE SIZE (1..MAX) OF NonceResponse
 * NonceResponse ::= SEQUENCE {
 * nonce  OCTET STRING,
 * -- contains the nonce of length len
 * -- provided by the Verifier indicated with hint
 * expiry INTEGER OPTIONAL,
 * -- indicates how long in seconds the Verifier considers
 * -- the nonce valid
 * type   EVIDENCE-STATEMENT.&id({EvidenceStatementSet}) OPTIONAL,
 * -- indicates which Evidence type to request a nonce for
 * hint UTF8String OPTIONAL
 * -- indicates which Verifier to request a nonce from
 * vendorextension OCTET STRING OPTIONAL
 * -- Siemens proprietary extension to carry additional data
 * }
 * }
 */
public class NonceResponseValue extends ASN1Object {

    ASN1EncodableVector nonceResponses = new ASN1EncodableVector();

    public static class NonceResponse extends ASN1Object {

        private final ASN1OctetString nonce;
        private ASN1Integer expiry = null;
        private ASN1ObjectIdentifier type = null;
        private ASN1UTF8String hint = null;
        private ASN1OctetString vendorextension = null;

        public ASN1Primitive toASN1Primitive() {

            ASN1EncodableVector v = new ASN1EncodableVector(4);

            v.add(nonce);
            addOptional(v, expiry);
            addOptional(v, type);
            addOptional(v, hint);
            addOptional(v, vendorextension);

            return new DERSequence(v);
        }

        public static NonceResponse getInstance(Object o) {
            if (o instanceof NonceResponse) {
                return (NonceResponse) o;
            } else if (o != null) {
                return new NonceResponse(ASN1Sequence.getInstance(o));
            }
            return null;
        }

        private NonceResponse(ASN1Sequence seq) {
            Enumeration<?> en = seq.getObjects();
            if (!en.hasMoreElements()) {
                throw new IllegalArgumentException("NonceResponse missing nonce value");
            }
            Object next = en.nextElement();
            nonce = ASN1OctetString.getInstance(next);
            if (!en.hasMoreElements()) {
                return;
            }
            next = en.nextElement();
            if (next instanceof ASN1Integer) {
                expiry = ASN1Integer.getInstance(next);
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
            if (next instanceof ASN1UTF8String) {
                hint = ASN1UTF8String.getInstance(next);
                if (!en.hasMoreElements()) {
                    return;
                }
                next = en.nextElement();
            }
            if (next instanceof ASN1OctetString) {
                vendorextension = ASN1OctetString.getInstance(next);
            }
        }

        public NonceResponse(
                ASN1OctetString nonce,
                ASN1Integer expiry,
                ASN1ObjectIdentifier type,
                ASN1UTF8String hint,
                ASN1OctetString vendorextension) {
            this.nonce = nonce;
            this.expiry = expiry;
            this.type = type;
            this.hint = hint;
            this.vendorextension = vendorextension;
        }

        public NonceResponse(byte[] nonce, Integer expiry, String type, String hint, byte[] vendorextension) {
            this(
                    nonce != null ? new DEROctetString(nonce) : null,
                    expiry != null ? new ASN1Integer(expiry) : null,
                    type != null ? new ASN1ObjectIdentifier(type) : null,
                    hint != null ? new DERUTF8String(hint) : null,
                    vendorextension != null ? new DEROctetString(vendorextension) : null);
        }

        public ASN1OctetString getNonce() {
            return nonce;
        }

        public ASN1Integer getExpiry() {
            return expiry;
        }

        public ASN1ObjectIdentifier getType() {
            return type;
        }

        public ASN1UTF8String getHint() {
            return hint;
        }

        public ASN1OctetString getVendorextension() {
            return vendorextension;
        }

        private void addOptional(ASN1EncodableVector v, ASN1Encodable obj) {
            if (obj != null) {
                v.add(obj);
            }
        }
    }

    public NonceResponseValue(ASN1Sequence instance) {
        for (int i = 0; i < instance.size(); i++) {
            nonceResponses.add(instance.getObjectAt(i));
        }
    }

    public NonceResponseValue(NonceResponse[] responses) {
        nonceResponses.addAll(responses);
    }

    public NonceResponse[] getNonceResponse() {
        NonceResponse[] ret = new NonceResponse[nonceResponses.size()];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = NonceResponse.getInstance(nonceResponses.get(i));
        }
        return ret;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(nonceResponses);
    }

    public static NonceResponseValue getInstance(Object o) {
        if (o instanceof NonceResponseValue) {
            return (NonceResponseValue) o;
        } else if (o != null) {
            return new NonceResponseValue(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
