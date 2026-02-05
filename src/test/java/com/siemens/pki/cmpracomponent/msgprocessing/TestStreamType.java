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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit tests for {@link StreamType}.
 *
 * <p>
 * This test class validates construction, factory methods, direction helpers, normalization rules,
 * inversion behavior, record accessors, and {@link StreamType#toString()} formatting.
 * </p>
 *
 * <p>
 * All functionality of the record is covered.
 * </p>
 */
public class TestStreamType {

    /**
     * Verifies that the canonical constructor trims the name and preserves the direction.
     */
    @Test
    public void testConstructorTrimsName() {
        StreamType st = new StreamType("  MyStream  ", StreamDirection.UPSTREAM);
        assertEquals("MyStream", st.name());
        assertSame(StreamDirection.UPSTREAM, st.direction());
    }

    /**
     * Ensures that a null name results in a NullPointerException.
     */
    @Test(expected = NullPointerException.class)
    public void testConstructorRejectsNullName() {
        new StreamType(null, StreamDirection.UPSTREAM);
    }

    /**
     * Ensures that a null direction results in a NullPointerException.
     */
    @Test(expected = NullPointerException.class)
    public void testConstructorRejectsNullDirection() {
        new StreamType("X", null);
    }

    /**
     * Verifies that blank names are rejected with IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testConstructorRejectsBlankName() {
        new StreamType("   ", StreamDirection.DOWNSTREAM);
    }

    /**
     * Tests the {@link StreamType#upstream(String)} factory method.
     */
    @Test
    public void testUpstreamFactory() {
        StreamType st = StreamType.upstream("UP");
        assertEquals("UP", st.name());
        assertSame(StreamDirection.UPSTREAM, st.direction());
        assertTrue(st.isUpstream());
        assertFalse(st.isDownstream());
    }

    /**
     * Tests the {@link StreamType#downstream(String)} factory method.
     */
    @Test
    public void testDownstreamFactory() {
        StreamType st = StreamType.downstream("DOWN");
        assertEquals("DOWN", st.name());
        assertSame(StreamDirection.DOWNSTREAM, st.direction());
        assertTrue(st.isDownstream());
        assertFalse(st.isUpstream());
    }

    /**
     * Tests {@link StreamType#of(String, StreamDirection)} as a pass-through constructor.
     */
    @Test
    public void testOfFactory() {
        StreamType st = StreamType.of("TestStream", StreamDirection.DOWNSTREAM);
        assertEquals("TestStream", st.name());
        assertSame(StreamDirection.DOWNSTREAM, st.direction());
    }

    /**
     * Ensures {@link StreamType#isUpstream()} delegates correctly to the direction enum.
     */
    @Test
    public void testIsUpstream() {
        assertTrue(StreamType.upstream("X").isUpstream());
        assertFalse(StreamType.downstream("Y").isUpstream());
    }

    /**
     * Ensures {@link StreamType#isDownstream()} delegates correctly to the direction enum.
     */
    @Test
    public void testIsDownstream() {
        assertTrue(StreamType.downstream("A").isDownstream());
        assertFalse(StreamType.upstream("B").isDownstream());
    }

    /**
     * Tests the invert() method returns a new StreamType with the same name and opposite
     * {@link StreamDirection}.
     */
    @Test
    public void testInvert() {
        StreamType up = StreamType.upstream("S");
        StreamType down = up.invert();
        assertEquals("S", down.name());
        assertSame(StreamDirection.DOWNSTREAM, down.direction());

        // invert twice = original
        assertEquals(up, down.invert());
    }

    /**
     * Ensures that {@link StreamType#toString()} produces the expected human-readable form.
     */
    @Test
    public void testToStringFormat() {
        StreamType st = StreamType.upstream("Alpha");
        String s = st.toString();
        assertNotNull(s);
        assertTrue(s.contains("Alpha"));
        assertTrue(s.contains("UPSTREAM"));
        assertEquals("Alpha (UPSTREAM)", s);
    }
}
