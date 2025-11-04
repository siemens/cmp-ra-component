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

import static org.junit.Assert.*;

import com.siemens.pki.verifieradapter.asn1.NonceRequestValue.NonceRequest;
import com.siemens.pki.verifieradapter.asn1.NonceResponseValue.NonceResponse;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.Test;

/**
 * test some unusual parameter combinations to improve test coverage
 */
public class TestRatAsn1 {

    @Test
    public void testAttestationResultBundle() throws IOException {
        byte[] encoded = new AttestationResultBundle(
                        new AttestationResult[] {
                            new AttestationResult(new ASN1ObjectIdentifier("1.2.3"), new DERUTF8String("hallo"))
                        },
                        null)
                .getEncoded();
        AttestationResultBundle decoded = AttestationResultBundle.getInstance(encoded);
        assertEquals(1, decoded.getResults().length);
        final AttestationResult attestationResult = decoded.getResults()[0];
        assertEquals(new ASN1ObjectIdentifier("1.2.3"), attestationResult.getType());
        assertEquals(new DERUTF8String("hallo"), attestationResult.getStmt());
        assertNull(decoded.getCerts());
    }

    @Test
    public void testEvidenceBundle() throws IOException {
        byte[] encoded = new EvidenceBundle(
                        new EvidenceStatement[] {
                            new EvidenceStatement(new ASN1ObjectIdentifier("1.2.3"), new DERUTF8String("hallo"), null)
                        },
                        null)
                .getEncoded();
        EvidenceBundle decoded = EvidenceBundle.getInstance(encoded);
        assertEquals(1, decoded.getEvidences().length);
        final EvidenceStatement evidenceStatement = decoded.getEvidences()[0];
        assertEquals(new ASN1ObjectIdentifier("1.2.3"), evidenceStatement.getType());
        assertEquals(new DERUTF8String("hallo"), evidenceStatement.getStmt());
        assertNull(evidenceStatement.getHint());
        assertNull(decoded.getCerts());
    }

    @Test
    public void testNonceRequestValue() throws IOException {
        byte[] encoded = new NonceRequestValue(new NonceRequest[] {new NonceRequest((BigInteger) null, null, null)})
                .getEncoded();
        NonceRequestValue decoded = NonceRequestValue.getInstance(encoded);
        assertEquals(1, decoded.getNonceRequests().length);
        final NonceRequest nonceRequest = decoded.getNonceRequests()[0];
        assertNull(nonceRequest.getLen());
        assertNull(nonceRequest.getType());
        assertNull(nonceRequest.getHint());
    }

    @Test
    public void testNonceResponseValue() throws IOException {
        byte[] encoded = new NonceResponseValue(new NonceResponse[] {new NonceResponse(new byte[10], null, null, null)})
                .getEncoded();
        NonceResponseValue decoded = NonceResponseValue.getInstance(encoded);
        assertEquals(1, decoded.getNonceResponse().length);
        final NonceResponse nonceRequest = decoded.getNonceResponse()[0];
        assertNotNull(nonceRequest.getNonce());
        assertNull(nonceRequest.getExpiry());
        assertNull(nonceRequest.getType());
        assertNull(nonceRequest.getHint());
    }
}
