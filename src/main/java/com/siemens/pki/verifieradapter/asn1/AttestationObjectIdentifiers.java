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
package com.siemens.pki.verifieradapter.asn1;

/**
 * OID definition from
 * https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/ and
 * https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/
 */
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * OIDs from from https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/ and
 * https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/
 */
public interface AttestationObjectIdentifiers {

    /**
     *  Branch for attestation statement types
     */
    /** RFC 4120: id-it: PKIX.4 = 1.3.6.1.5.5.7.4 */
    ASN1ObjectIdentifier id_it = X509ObjectIdentifiers.id_pkix.branch("4");

    /**
     * from https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/
     * TODO update to current state of the draft
     */
    String TBD1 = "99";

    String TBD2 = "100";
    String TBD3 = "101";

    ASN1ObjectIdentifier id_it_NonceRequest = id_it.branch(TBD1);
    ASN1ObjectIdentifier id_it_NonceResponse = id_it.branch(TBD2);

    /**
     * from https://datatracker.ietf.org/doc/draft-ietf-lamps-csr-attestation/
     */
    ASN1ObjectIdentifier id_aa_evidence = PKCSObjectIdentifiers.id_aa.branch("59");

    ASN1ObjectIdentifier id_aa_ar = PKCSObjectIdentifiers.id_aa.branch(TBD3);
}
