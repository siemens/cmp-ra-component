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
package com.siemens.pki.cmpracomponent.persistency;

import static com.siemens.pki.cmpracomponent.testutil.TestCertificates.newCert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.junit.Test;

/**
 * Unit tests for {@link PersistencyContext} focusing exclusively on the getter/setter pairs used to
 * track extra certificates that have already been sent upstream or downstream in a CMP transaction.
 *
 * <h2>Purpose</h2>
 * <p>
 * The {@link PersistencyContext} stores certificates that were previously sent in either direction
 * (upstream or downstream). This allows CMP message processing logic to suppress redundant
 * <code>extraCerts</code>. These tests validate:
 * </p>
 *
 * <ul>
 * <li>Correct lazy initialization of internal sets</li>
 * <li>Correct behavior of setter methods when passed <code>null</code></li>
 * <li>Defensive copying semantics (external mutation cannot affect internal state)</li>
 * <li>Mutability of returned sets</li>
 * <li>Guarantee that getters always return non-null sets</li>
 * <li>Verification that calls return the same initialized set instance</li>
 * </ul>
 *
 * <h2>Scope</h2>
 * <p>
 * These tests do <strong>not</strong> validate any message-processing behavior, certificate
 * semantics, or integration logic. They only cover the persistence container used by higher-level
 * CMP components.
 * </p>
 *
 * <h2>Why This Matters</h2>
 * <p>
 * Message processors rely on these sets to determine whether an <code>extraCert</code> was already
 * forwarded. Incorrect behavior here could lead to:
 * </p>
 *
 * <ul>
 * <li>duplicate certificates in message output</li>
 * <li>state leaks across requests</li>
 * <li>incorrect suppression behavior</li>
 * </ul>
 *
 * <p>
 * Ensuring these setters/getters behave correctly is essential for reliable CMP extraCert
 * suppression.
 * </p>
 */
public class TestPersistencyContext {

    /**
     * Verifies that calling {@link PersistencyContext#getAlreadySentExtraCertsToUpStream()} lazily
     * initializes an empty, non-null set and returns the same set instance on repeated calls when no
     * setter has overridden it.
     */
    @Test
    public void testUpstreamGetterLazyInit() {
        PersistencyContext pc = new PersistencyContext();

        Set<CMPCertificate> set = pc.getAlreadySentExtraCertsToUpStream();
        assertNotNull(set);
        assertTrue(set.isEmpty());

        // Ensure the same instance is returned again (no recreation)
        assertSame(set, pc.getAlreadySentExtraCertsToUpStream());
    }

    /**
     * Tests that calling {@link PersistencyContext#setAlreadySentExtraCertsToUpStream(Set)} with
     * <code>null</code> resets the upstream-known set to an empty, newly allocated set.
     */
    @Test
    public void testUpstreamSetterWithNullResetsSet() {
        PersistencyContext pc = new PersistencyContext();

        // Pre-populate
        Set<CMPCertificate> initial = pc.getAlreadySentExtraCertsToUpStream();
        initial.add(newCert("K"));
        assertEquals(1, initial.size());

        // Now call setter with null
        pc.setAlreadySentExtraCertsToUpStream(null);

        Set<CMPCertificate> newSet = pc.getAlreadySentExtraCertsToUpStream();
        assertNotNull(newSet);
        assertTrue(newSet.isEmpty()); // reset to empty
        assertNotSame(initial, newSet); // new set, not the old one
    }

    /**
     * Ensures that the upstream setter correctly makes a defensive copy of the provided set, rather
     * than storing the instance directly. Mutations to the caller-provided set must not affect the
     * internal set.
     */
    @Test
    public void testUpstreamSetterMakesDefensiveCopy() {
        PersistencyContext pc = new PersistencyContext();

        CMPCertificate c1 = newCert("K");
        Set<CMPCertificate> external = new HashSet<>();
        external.add(c1);

        pc.setAlreadySentExtraCertsToUpStream(external);

        Set<CMPCertificate> internal = pc.getAlreadySentExtraCertsToUpStream();
        assertEquals(1, internal.size());
        assertTrue(internal.contains(c1));

        // Mutating external must NOT affect internal
        external.clear();
        assertEquals(1, internal.size());
    }

    /**
     * Validates that the upstream getter returns a mutable set, allowing callers to append additional
     * certificates during processing.
     */
    @Test
    public void testUpstreamGetterReturnsMutableSet() {
        PersistencyContext pc = new PersistencyContext();

        Set<CMPCertificate> set = pc.getAlreadySentExtraCertsToUpStream();
        CMPCertificate c = newCert("K");
        set.add(c); // should NOT throw
        assertTrue(pc.getAlreadySentExtraCertsToUpStream().contains(c));
    }

    // ----- DOWNSTREAM TESTS -----

    /**
     * Verifies lazy initialization for the downstream-known extraCert set.
     */
    @Test
    public void testDownstreamGetterLazyInit() {
        PersistencyContext pc = new PersistencyContext();

        Set<CMPCertificate> set = pc.getAlreadySentExtraCertsToDownStream();
        assertNotNull(set);
        assertTrue(set.isEmpty());

        // Ensure same instance returned
        assertSame(set, pc.getAlreadySentExtraCertsToDownStream());
    }

    /**
     * Ensures that setting the downstream-known set to <code>null</code> correctly resets it to a
     * fresh, empty set.
     */
    @Test
    public void testDownstreamSetterWithNullResetsSet() {
        PersistencyContext pc = new PersistencyContext();

        Set<CMPCertificate> old = pc.getAlreadySentExtraCertsToDownStream();
        old.add(newCert("K"));
        assertEquals(1, old.size());

        pc.setAlreadySentExtraCertsToDownStream(null);

        Set<CMPCertificate> newSet = pc.getAlreadySentExtraCertsToDownStream();
        assertNotNull(newSet);
        assertTrue(newSet.isEmpty());
        assertNotSame(old, newSet);
    }

    /**
     * Validates that the downstream setter makes a defensive copy of its argument and that mutations
     * to the caller-supplied set do not affect the internal state.
     */
    @Test
    public void testDownstreamSetterMakesDefensiveCopy() {
        PersistencyContext pc = new PersistencyContext();

        CMPCertificate c1 = newCert("K");
        Set<CMPCertificate> external = new HashSet<>();
        external.add(c1);

        pc.setAlreadySentExtraCertsToDownStream(external);

        Set<CMPCertificate> internal = pc.getAlreadySentExtraCertsToDownStream();
        assertTrue(internal.contains(c1));

        external.clear();
        assertEquals(1, internal.size()); // unchanged
    }

    /**
     * Ensures that the downstream getter returns a mutable set that callers can modify when
     * additional certificates are forwarded.
     */
    @Test
    public void testDownstreamGetterReturnsMutableSet() {
        PersistencyContext pc = new PersistencyContext();

        Set<CMPCertificate> set = pc.getAlreadySentExtraCertsToDownStream();
        CMPCertificate c = newCert("K");
        set.add(c);
        assertTrue(pc.getAlreadySentExtraCertsToDownStream().contains(c));
    }
}
