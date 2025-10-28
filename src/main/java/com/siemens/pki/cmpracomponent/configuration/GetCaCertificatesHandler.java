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
package com.siemens.pki.cmpracomponent.configuration;

import java.security.cert.X509Certificate;
import java.util.List;

/** support message handler supporting Get CA certificates GENM requests */
public interface GetCaCertificatesHandler extends SupportMessageHandlerInterface {

    /**
     * handle an Get CA certificates GENM request and return certificates to build the related GENP response
     *
     * @return certificates to be returned or <code>null</code> if the returned infoValue should be absent
     */
    List<X509Certificate> getCaCertificates();
}
