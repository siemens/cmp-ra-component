/*
 * Copyright (c) 2024 Siemens AG
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

package com.siemens.pki.cmpracomponent.msgvalidation;

import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;

/**
 * Container class to store @link{PersistencyContext} and @link{CredentialContext} of a PKI message
 */
public class MessageContext {

    final PersistencyContext persistencyContext;
    final CredentialContext credentialContext;

    /**
     * Class constructor
     * @param persistency   a persistency context
     * @param credentials   a credential context
     */
    public MessageContext(PersistencyContext persistency, CredentialContext credentials) {
        persistencyContext = persistency;
        credentialContext = credentials;
    }

    /**
     * provide a persistency context
     * @return a persistency context
     */
    public PersistencyContext getPersistencyContext() {
        return persistencyContext;
    }

    /**
     * provide a credential context configuration usable for message protection
     * @return  a credential context
     */
    public CredentialContext getCredentialContext() {
        return credentialContext;
    }
}
