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
 * support message handler supporting Get certificate request template genm
 * requests
 */
public interface GetCertificateRequestTemplateHandler extends SupportMessageHandlerInterface {

    /**
     * handle an Get certificate request template GENM and return a ASN.1 DER
     * encoded template
     *
     * @return template to be returned or <code>null</code> if the returned
     *         infoValue should be absent
     */
    byte[] getCertificateRequestTemplate();
}
