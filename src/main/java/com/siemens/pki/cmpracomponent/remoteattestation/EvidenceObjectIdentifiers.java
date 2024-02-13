/*
 *  Copyright (c) 2023 Siemens AG
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
package com.siemens.pki.cmpracomponent.remoteattestation;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public interface EvidenceObjectIdentifiers {

    // https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/
    /**
     *  Branch for attestation statement types
     */
    // id-pkix (TBD1)
    ASN1ObjectIdentifier ata = new ASN1ObjectIdentifier("1.7.6.5");

    ASN1ObjectIdentifier attestation_result = ata.branch("123");

    ASN1ObjectIdentifier aa_evidenceStatement = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.999");

    ASN1ObjectIdentifier aa_nonce = PKCSObjectIdentifiers.id_aa.branch("8888");
}
