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

import java.util.Objects;

/**
 * Represents a typed message stream within the CMP RA component.
 * <p>
 * A {@code StreamType} combines a human-readable name with a specific
 * {@link StreamDirection}, indicating whether messages on this stream
 * flow upstream or downstream through the message-processing pipeline.
 * </p>
 *
 * @param name
 *            the logical name of the stream; must not be {@code null} or blank
 * @param direction
 *            the direction of the stream; must not be {@code null}
 */
public record StreamType(String name, StreamDirection direction) {

    /**
     * Creates a {@code StreamType} that flows in the upstream direction.
     *
     * @param name
     *            the logical name of the stream
     * @return a new {@code StreamType} with direction {@link StreamDirection#UPSTREAM}
     */
    public static StreamType upstream(String name) {
        return new StreamType(name, StreamDirection.UPSTREAM);
    }

    /**
     * Creates a {@code StreamType} that flows in the downstream direction.
     *
     * @param name
     *            the logical name of the stream
     * @return a new {@code StreamType} with direction {@link StreamDirection#DOWNSTREAM}
     */
    public static StreamType downstream(String name) {
        return new StreamType(name, StreamDirection.DOWNSTREAM);
    }

    /**
     * Creates a {@code StreamType} with the specified direction.
     *
     * @param name
     *            the logical name of the stream
     * @param direction
     *            the direction the stream flows
     * @return a new {@code StreamType}
     */
    public static StreamType of(String name, StreamDirection direction) {
        return new StreamType(name, direction);
    }

    /**
     * Validates constructor arguments and normalizes the stream name.
     *
     * @throws NullPointerException
     *             if {@code name} or {@code direction} is {@code null}
     * @throws IllegalArgumentException
     *             if {@code name} is blank
     */
    public StreamType {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(direction, "direction must not be null");

        final String trimmed = name.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        name = trimmed;
    }

    /**
     * Returns whether this stream flows in the upstream direction.
     *
     * @return {@code true} if the stream direction is {@link StreamDirection#UPSTREAM}
     */
    public boolean isUpstream() {
        return direction.isUpstream();
    }

    /**
     * Returns whether this stream flows in the downstream direction.
     *
     * @return {@code true} if the stream direction is {@link StreamDirection#DOWNSTREAM}
     */
    public boolean isDownstream() {
        return direction.isDownstream();
    }

    /**
     * Returns a new {@code StreamType} with the same name but the opposite direction.
     *
     * @return a new {@code StreamType} with inverted {@link StreamDirection}
     */
    public StreamType invert() {
        return new StreamType(name, direction.opposite());
    }

    /**
     * Returns a human-readable representation of the stream type in the form:
     * <pre>
     *     &lt;name&gt; (&lt;direction&gt;)
     * </pre>
     *
     * @return string representation of this stream type
     */
    @Override
    public String toString() {
        return name + " (" + direction + ")";
    }
}
