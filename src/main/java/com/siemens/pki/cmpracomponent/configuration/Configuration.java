/*
 *  Copyright (c) 2022 Siemens AG
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
package com.siemens.pki.cmpracomponent.configuration;

/**
 * the {@link Configuration} specifies the behavior of the generic RA component.
 */
public interface Configuration {
    // @see doc/API/design.md

    /**
     * specify configuration needed to support central key generation
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    response PKI Message Body type
     * @return configuration for central key generation
     */
    CkgContext getCkgConfiguration(String certProfile, int bodyType);

    /**
     * specify configuration for the downstream CMP interface towards the end entity
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request/response PKI Message Body type
     * @return the downstream interface configuration
     */
    CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType);
    /**
     * get the time in seconds after last response to downstream when an unfinished transaction should be forgotten
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request/response PKI Message Body type
     * @return maximum transaction lifetime after last downstream interaction in seconds. the value 0 disables the timeout.
     */
    int getDownstreamTimeout(String certProfile, int bodyType);

    /**
     * provide VerificationContext used to validate an enrolled certificate and to
     * calculate the additional certificates in the extraCerts field of IP, CP and
     * KUP.
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    response PKI Message Body type
     * @return an VerificationContext related to the enrolled certificate
     */
    VerificationContext getEnrollmentTrust(String certProfile, int bodyType);

    /**
     * allow to set POPO to RaVerified for outgoing upstream IR, CR, KUR
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request PKI Message Body type
     * @return <code>true</code> if RaVerified should be set
     */
    boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType);

    /**
     * optionally access function to external InventoryFunction
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request/response PKI Message Body type
     * @return external InventoryFunction or <code>null</code>
     */
    InventoryInterface getInventory(String certProfile, int bodyType);

    /**
     * provide a persistence implementation
     *
     * @return persistence implementation
     */
    default PersistencyInterface getPersistency() {
        return new PersistencyInterface() {};
    }

    /**
     * specify the retryAfter time in seconds to return on the downstream interface
     * in case of delayed delivery (polling)
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request PKI Message Body type
     * @return retryAfter time in seconds
     */
    int getRetryAfterTimeInSeconds(String certProfile, int bodyType);

    /**
     * return a handler instance able to handle the given infoType extracted from an
     * GENM PKI message
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param infoTypeOid infoType OID extracted from an GENM PKI message
     * @return a handler instance or <code>null</code> if the GENM shall be
     * forwarded to the next upstream PKI management entity
     */
    SupportMessageHandlerInterface getSupportMessageHandler(String certProfile, String infoTypeOid);

    /**
     * specify configuration for the upstream CMP interface towards the CA
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request PKI Message Body type
     * @return the upstream interface configuration
     */
    CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType);

    /**
     * configure if a POPO of RaVerified for incoming IR, CR, KUR is acceptable
     *
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request PKI Message Body type
     * @return <code>false</code> if a signature-based POPO must be provided.
     */
    boolean isRaVerifiedAcceptable(String certProfile, int bodyType);
}
