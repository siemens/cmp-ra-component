/*
 *  Copyright (c) 2026 Siemens AG
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
package com.siemens.pki.cmpracomponent.msggeneration;

import static com.siemens.pki.cmpracomponent.testutil.TestCertificates.newCert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.msgprocessing.StreamType;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import java.security.GeneralSecurityException;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Test;

/**
 * Unit tests for {@link MsgOutputProtector#stripRedundantExtraCerts(PKIMessage)}.
 *
 * <h2>Purpose</h2>
 * <p>
 * These tests validate the behavior of the <em>extraCerts suppression</em> mechanism in
 * {@link MsgOutputProtector}. When suppression is enabled, redundant certificates (already
 * forwarded earlier in the same CMP transaction) must be removed from outgoing {@link PKIMessage}
 * instances, and the {@link PersistencyContext} must be updated to record newly forwarded
 * certificates.
 * </p>
 *
 * <h2>Key Behaviors Verified</h2>
 * <ul>
 * <li>Certificates already known in the relevant persistency set are removed.</li>
 * <li>Remaining certificates preserve their original order.</li>
 * <li>If all certificates are redundant, {@code extraCerts} is set to {@code null}.</li>
 * <li>Newly forwarded certificates are added to the appropriate persistency set.</li>
 * <li>The persistency set used depends on message {@link StreamType}:
 * <ul>
 * <li><strong>Downstream</strong> →
 * {@link PersistencyContext#getAlreadySentExtraCertsToDownStream()}</li>
 * <li><strong>Upstream</strong> →
 * {@link PersistencyContext#getAlreadySentExtraCertsToUpStream()}</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Test Design</h2>
 * <p>
 * Minimal but valid {@link PKIMessage} structures are constructed for each scenario. The body uses
 * <code>TYPE_CONFIRM</code> with {@link DERNull#INSTANCE}, which is fully compliant with CMP’s
 * PKIConfirmContent and avoids unnecessary complexity.
 * </p>
 * <p>
 * Real X.509 ASN.1 certificates are created using the test utility
 * {@link com.siemens.pki.cmpracomponent.testutil.TestCertificates#newCert(String)} to ensure
 * realistic equality and set semantics.
 * </p>
 *
 * <h2>Test Environment Assumptions</h2>
 * <ul>
 * <li>The {@link MsgOutputProtector} is configured with {@code ReprotectMode.keep}, enforced via
 * the test-local {@link CmpMessageInterface} stub.</li>
 * <li>Shared-secret output credentials are sufficient and avoid signature‑based reprotection.</li>
 * <li>{@link PersistencyContext} lazily initializes and exposes mutable sets.</li>
 * </ul>
 *
 * <h2>Out of Scope</h2>
 * <ul>
 * <li>Cryptographic correctness of protection creation</li>
 * <li>Testing reprotect/strip modes other than {@code keep}</li>
 * <li>End‑to‑end CMP message flows</li>
 * </ul>
 */
public class TestMsgOutputProtector {

    /** Dummy protection algorithm identifier used to build minimal PKIHeader instances. */
    private static final AlgorithmIdentifier DUMMY_ALG = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5"));

    /**
     * Creates a minimal {@link PKIMessage} containing an optional set of extra certificates.
     *
     * <p>
     * The body is always CMP Confirm (TYPE_CONFIRM) with {@link DERNull#INSTANCE}. This is sufficient
     * for exercising the extraCerts suppression logic while avoiding unnecessary message complexity.
     * </p>
     *
     * @param extra optional extraCerts to embed into the message
     * @return a valid, lightweight {@link PKIMessage} instance
     */
    private PKIMessage newMsg(CMPCertificate... extra) {
        PKIHeader hdr = new PKIHeaderBuilder(
                        PKIHeader.CMP_2000,
                        new GeneralName(new X500Name("CN=SENDER")),
                        new GeneralName(new X500Name("CN=RECIPIENT")))
                .setProtectionAlg(DUMMY_ALG)
                .build();

        PKIBody body = new PKIBody(PKIBody.TYPE_CONFIRM, DERNull.INSTANCE);
        DERBitString prot = new DERBitString(new byte[] {1}); // dummy protection

        return new PKIMessage(hdr, body, prot, (extra == null || extra.length == 0) ? null : extra);
    }

    /**
     * Constructs a {@link MsgOutputProtector} suitable for suppression tests.
     *
     * <p>
     * The returned instance:
     * </p>
     * <ul>
     * <li>uses {@code ReprotectMode.keep}</li>
     * <li>enforces reprotection mode</li>
     * <li>performs or skips extraCerts suppression based on the {@code suppress} flag</li>
     * <li>uses simple shared-secret credentials for output</li>
     * <li>relies on a provided {@link PersistencyContext} and {@link StreamType}</li>
     * </ul>
     *
     * @param suppress whether redundant extraCerts should be stripped
     * @param pc persistency context used to track sent certificates
     * @param st direction of message flow (upstream or downstream)
     * @return a fully constructed {@link MsgOutputProtector} for testing
     */
    private MsgOutputProtector protector(boolean suppress, PersistencyContext pc, StreamType st)
            throws GeneralSecurityException, CmpProcessingException {

        CmpMessageInterface cfg = new CmpMessageInterface() {
            @Override
            public VerificationContext getInputVerification() {
                return null;
            }

            @Override
            public NestedEndpointContext getNestedEndpointContext() {
                return null;
            }

            @Override
            public CredentialContext getOutputCredentials() {
                return null;
            }

            @Override
            public ReprotectMode getReprotectMode() {
                return ReprotectMode.keep;
            }

            @Override
            public boolean isEnforceReprotectMode() {
                return true;
            }

            @Override
            public boolean getSuppressRedundantExtraCerts() {
                return suppress;
            }

            @Override
            public boolean isCacheExtraCerts() {
                return false;
            }

            @Override
            public boolean isMessageTimeDeviationAllowed(long d) {
                return true;
            }
        };

        SharedSecretCredentialContext cred = new SharedSecretCredentialContext() {
            @Override
            public byte[] getSharedSecret() {
                return "s".getBytes();
            }
        };

        MessageContext mc = new MessageContext(pc, cred);
        return new MsgOutputProtector(cfg, st, mc);
    }

    /**
     * Tests partial redundancy in <strong>downstream</strong> mode:
     * <ul>
     * <li>known → stripped</li>
     * <li>fresh → forwarded</li>
     * <li>fresh → added to downstream-known set</li>
     * </ul>
     */
    @Test
    public void downstream_partialRedundancy() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate known = newCert("K");
        CMPCertificate fresh = newCert("F");

        pc.getAlreadySentExtraCertsToDownStream().add(known);

        MsgOutputProtector p = protector(true, pc, StreamType.downstream("DOWN"));
        PKIMessage out = p.stripRedundantExtraCerts(newMsg(known, fresh));

        assertEquals(1, out.getExtraCerts().length);
        assertSame(fresh, out.getExtraCerts()[0]);
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(fresh));

        assertEquals(2, pc.getAlreadySentExtraCertsToDownStream().size());
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().containsAll(List.of(known, fresh)));
    }

    /**
     * Tests partial redundancy in <strong>upstream</strong> mode, mirroring the downstream test but
     * verifying use of the upstream persistency set.
     */
    @Test
    public void upstream_partialRedundancy() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate known = newCert("K");
        CMPCertificate fresh = newCert("F");

        pc.getAlreadySentExtraCertsToUpStream().add(known);

        MsgOutputProtector p = protector(true, pc, StreamType.upstream("UP"));
        PKIMessage out = p.stripRedundantExtraCerts(newMsg(known, fresh));

        assertEquals(1, out.getExtraCerts().length);
        assertSame(fresh, out.getExtraCerts()[0]);
        assertTrue(pc.getAlreadySentExtraCertsToUpStream().contains(fresh));

        assertEquals(2, pc.getAlreadySentExtraCertsToUpStream().size());
        assertTrue(pc.getAlreadySentExtraCertsToUpStream().containsAll(List.of(known, fresh)));
    }

    /**
     * Ensures that when all extraCerts are redundant in downstream mode, the result contains
     * {@code extraCerts == null}.
     */
    @Test
    public void downstream_allRedundant() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate a = newCert("A");

        pc.getAlreadySentExtraCertsToDownStream().add(a);

        MsgOutputProtector p = protector(true, pc, StreamType.downstream("DOWN"));
        PKIMessage out = p.stripRedundantExtraCerts(newMsg(a));

        assertNull(out.getExtraCerts());
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(a));
    }

    /**
     * Verifies that the order of remaining extraCerts is preserved after stripping.
     */
    @Test
    public void orderPreserved() throws Exception {
        PersistencyContext pc = new PersistencyContext();
        CMPCertificate a = newCert("A");
        CMPCertificate b = newCert("B");
        CMPCertificate c = newCert("C");

        pc.getAlreadySentExtraCertsToDownStream().add(b);

        MsgOutputProtector p = protector(true, pc, StreamType.downstream("DOWN"));
        PKIMessage out = p.stripRedundantExtraCerts(newMsg(a, b, c));

        CMPCertificate[] x = out.getExtraCerts();
        assertEquals(2, x.length);
        assertSame(a, x[0]);
        assertSame(c, x[1]);

        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(a));
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(c));
    }
}
