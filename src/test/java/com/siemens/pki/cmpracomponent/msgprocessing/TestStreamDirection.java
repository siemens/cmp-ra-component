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
package com.siemens.pki.cmpracomponent.msgprocessing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit tests for {@link StreamDirection} using JUnit 4.
 *
 * <p>
 * This class verifies full functional coverage of the enum, including:
 * </p>
 * <ul>
 * <li>Correct enum constants exposed through {@link StreamDirection#values()}</li>
 * <li>Resolution via {@link StreamDirection#valueOf(String)}</li>
 * <li>Behavior of {@link StreamDirection#isUpstream()} and
 * {@link StreamDirection#isDownstream()}</li>
 * <li>Correct opposite-direction semantics via {@link StreamDirection#opposite()}</li>
 * <li>Involution property: {@code opposite(opposite(x)) == x}</li>
 * <li>Sanity of {@link StreamDirection#toString()}</li>
 * </ul>
 */
public class TestStreamDirection {

    /**
     * Ensures that {@link StreamDirection#values()} returns exactly the expected two constants:
     * UPSTREAM and DOWNSTREAM.
     */
    @Test
    public void testValuesContainsBoth() {
        StreamDirection[] values = StreamDirection.values();
        assertEquals("Exactly two enum constants expected", 2, values.length);
        assertEquals(StreamDirection.UPSTREAM, values[0]);
        assertEquals(StreamDirection.DOWNSTREAM, values[1]);
    }

    /**
     * Tests that {@link StreamDirection#valueOf(String)} correctly resolves the enum constants by
     * their names.
     */
    @Test
    public void testValueOf() {
        assertSame(StreamDirection.UPSTREAM, StreamDirection.valueOf("UPSTREAM"));
        assertSame(StreamDirection.DOWNSTREAM, StreamDirection.valueOf("DOWNSTREAM"));
    }

    /**
     * Verifies that {@link StreamDirection#isUpstream()} and {@link StreamDirection#isDownstream()}
     * produce the correct truth values for the UPSTREAM constant.
     */
    @Test
    public void testUpstreamTruthValues() {
        StreamDirection dir = StreamDirection.UPSTREAM;
        assertTrue(dir.isUpstream());
        assertFalse(dir.isDownstream());
    }

    /**
     * Verifies that {@link StreamDirection#isUpstream()} and {@link StreamDirection#isDownstream()}
     * produce the correct truth values for the DOWNSTREAM constant.
     */
    @Test
    public void testDownstreamTruthValues() {
        StreamDirection dir = StreamDirection.DOWNSTREAM;
        assertFalse(dir.isUpstream());
        assertTrue(dir.isDownstream());
    }

    /**
     * Ensures UPSTREAM.opposite() returns DOWNSTREAM.
     */
    @Test
    public void testOppositeOfUpstream() {
        assertSame(StreamDirection.DOWNSTREAM, StreamDirection.UPSTREAM.opposite());
    }

    /**
     * Ensures DOWNSTREAM.opposite() returns UPSTREAM.
     */
    @Test
    public void testOppositeOfDownstream() {
        assertSame(StreamDirection.UPSTREAM, StreamDirection.DOWNSTREAM.opposite());
    }

    /**
     * Ensures that {@link StreamDirection#opposite()} is an involution: calling it twice returns the
     * original direction.
     */
    @Test
    public void testOppositeIsInvolution() {
        for (StreamDirection dir : StreamDirection.values()) {
            assertSame(dir, dir.opposite().opposite());
        }
    }

    /**
     * Verifies that {@link StreamDirection#isUpstream()} and {@link StreamDirection#isDownstream()}
     * are mutually exclusive.
     */
    @Test
    public void testIsUpstreamDownstreamMutuallyExclusive() {
        for (StreamDirection dir : StreamDirection.values()) {
            assertNotEquals(dir.isUpstream(), dir.isDownstream());
        }
    }

    /**
     * Tests that {@link StreamDirection#toString()} returns a non-empty string that contains the enum
     * constant’s name.
     */
    @Test
    public void testToStringContainsName() {
        for (StreamDirection dir : StreamDirection.values()) {
            String text = dir.toString();
            assertNotNull(text);
            assertFalse(text.isEmpty());
            assertTrue(text.contains(dir.name()));
        }
    }
}
