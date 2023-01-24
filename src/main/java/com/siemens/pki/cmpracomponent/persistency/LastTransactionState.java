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
package com.siemens.pki.cmpracomponent.persistency;

/**
 * current state of a transaction
 */
enum LastTransactionState {
    INITIAL_STATE,
    //
    CERTIFICATE_REQUEST_SENT,
    CERTIFICATE_RECEIVED,
    CERTIFICATE_CONFIRMEND,
    CONFIRM_CONFIRMED,
    CERTIFICATE_POLLING,
    //
    REVOCATION_SENT,
    REVOCATION_CONFIRMED,
    REVOCATION_POLLING,
    //
    GENM_RECEIVED,
    GENREP_RETURNED,
    GEN_POLLING,
    //
    IN_ERROR_STATE
}
