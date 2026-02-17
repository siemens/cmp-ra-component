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

/**
 * Defines the direction of message flow within the CMP RA component.
 * <p>
 * The stream direction determines whether a message is processed in the
 * upstream direction (moving toward a higher-level component, e.g.
 * Registration Authority → Certificate Authority) or in the downstream
 * direction (moving toward a lower-level endpoint, e.g.
 * CA → RA → End Entity).
 * </p>
 */
public enum StreamDirection {

    /**
     * Indicates that the message is travelling upstream in the processing
     * pipeline, typically a request from a client or lower-level system toward a
     * higher-level component.
     */
    UPSTREAM,

    /**
     * Indicates that the message is travelling downstream in the processing
     * pipeline, typically a response from a higher-level component toward a client or
     * lower-level system.
     */
    DOWNSTREAM;

    /**
     * Returns whether this direction represents upstream flow.
     *
     * @return {@code true} if the direction is {@link #UPSTREAM}
     */
    public boolean isUpstream() {
        return this == UPSTREAM;
    }

    /**
     * Returns whether this direction represents downstream flow.
     *
     * @return {@code true} if the direction is {@link #DOWNSTREAM}
     */
    public boolean isDownstream() {
        return this == DOWNSTREAM;
    }

    /**
     * Returns the opposite of the current stream direction.
     * <p>
     * For {@code UPSTREAM}, the opposite is {@code DOWNSTREAM};
     * for {@code DOWNSTREAM}, the opposite is {@code UPSTREAM}.
     * </p>
     *
     * @return the opposite {@link StreamDirection}
     */
    public StreamDirection opposite() {
        return this == UPSTREAM ? DOWNSTREAM : UPSTREAM;
    }
}
