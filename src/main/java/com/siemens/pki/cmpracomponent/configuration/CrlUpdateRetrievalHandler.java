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

import java.security.cert.X509CRL;
import java.util.Date;
import java.util.List;

/**
 * support message handler supporting CRL Update Retrieval genm requests
 */
public interface CrlUpdateRetrievalHandler
        extends SupportMessageHandlerInterface {
    /**
     * handle a CRL Update Retrieval genm request and return the CRLs to
     * build the related GENP response
     *
     * @param dpnFullName
     *            fullName from DistributionPointName in CRLSource or
     *            <code>null</code> if absent in request
     * @param dpnNameRelativeToCRLIssuer
     *            nameRelativeToCRLIssuer from DistributionPointName in
     *            CRLSource or <code>null</code> if absent in request
     * @param issuer
     *            issuer from CRLSource or <code>null</code> if
     *            absent in request
     * @param thisUpdate
     *            thisUpdate time from CRLStatus in request <code>null</code> if
     *            absent in request
     * @return CRLs to be returned or <code>null</code> if the returned
     *         infoValue should be absent
     */
    List<X509CRL> getCrls(String[] dpnFullName,
            String dpnNameRelativeToCRLIssuer, String[] issuer,
            Date thisUpdate);
}
