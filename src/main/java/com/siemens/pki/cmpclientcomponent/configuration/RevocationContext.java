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
package com.siemens.pki.cmpclientcomponent.configuration;

import java.math.BigInteger;
import java.security.cert.CRLReason;

/** revocation specific configuration */
public interface RevocationContext {
    /**
     * get issuer of certificate to revoke
     *
     * @return issuer of certificate to revoke
     */
    String getIssuer();

    /**
     * get revocation reason to use
     *
     * @return revocation reason
     */
    default int getRevocationReason() {
        return CRLReason.UNSPECIFIED.ordinal();
    }

    /**
     * get serial number of certificate to revoke
     *
     * @return serial number of certificate to revoke
     */
    BigInteger getSerialNumber();
}
