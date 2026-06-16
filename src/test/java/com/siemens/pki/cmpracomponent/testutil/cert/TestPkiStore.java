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
package com.siemens.pki.cmpracomponent.testutil.cert;

import com.siemens.pki.cmpracomponent.testutil.cert.PkiHierarchyGenerator.FullPki;

public final class TestPkiStore {

    private TestPkiStore() {}

    // Initialization-on-demand holder: thread-safe, lazy, no synchronization overhead after init
    private static class Holder {
        static final FullPki INSTANCE = init();

        private static FullPki init() {
            try {
                return new PkiHierarchyGenerator().generate();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize PKI test store", e);
            }
        }
    }

    public static FullPki get() {
        return Holder.INSTANCE;
    }
}
