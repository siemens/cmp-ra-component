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
package com.siemens.pki.cmpracomponent.msgprocessing;

import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import org.bouncycastle.asn1.cmp.PKIMessage;

/** representation of an CMP upstream interface of a RA */
interface RaUpstream {
    PKIMessage handleRequest(final PKIMessage in, final PersistencyContext pesistencyContext) throws BaseCmpException;
}
