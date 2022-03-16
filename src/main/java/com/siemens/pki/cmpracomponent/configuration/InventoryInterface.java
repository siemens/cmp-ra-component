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
 * interface to an external inventory
 * for checking/modifying certificate requests
 * and reporting enrollment results
 */
public interface InventoryInterface {

    /**
     * check and optionally modify a CRMF certificate request if an ir, cr or,
     * kur was received.
     * @param transactionID
     *            the transactionID of the CMP request message.
     *            The transactionID can be used to correlate calls of
     *            {@link #checkAndModifyCertRequest(byte[], String, byte[], String)},
     *            {@link #checkP10CertRequest(byte[], String, byte[], String)}
     *            and
     *            {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param requesterDn
     *            Distinguished Name (DN) of the CMP requester. This is the
     *            subject of the first certificate in the extraCerts field of
     *            the CMP request or the sender extracted from the PKI message
     *            header. If neither signature-based protection was used nor the
     *            sender field was set the requesterDn is <code>null</code>.
     * @param certTemplate
     *            the CertTemplate of the certificate request as received from
     *            the requester. The CertTemplate should be ASN.1 DER encoded.
     * @param requestedSubjectDn
     *            subject DN extracted from the CertTemplate of the request.
     *            This parameter is provided for convenience.
     *
     * @return result of validation check
     */
    CheckAndModifyResult checkAndModifyCertRequest(byte[] transactionID,
            String requesterDn, byte[] certTemplate, String requestedSubjectDn);

    /**
     * check PKCS#10 certificate request if a p10cr was received. Note that such
     * certificate request cannot be modified because it is self-signed by the
     * requester.
     * @param transactionID
     *            the transactionID of the CMP request message.
     *            The transactionID can be used to correlate calls of
     *            {@link #checkAndModifyCertRequest(byte[], String, byte[], String)},
     *            {@link #checkP10CertRequest(byte[], String, byte[], String)}
     *            and
     *            {@link #learnEnrollmentResult(byte[],byte[], String, String, String)}.
     * @param requesterDn
     *            Distinguished Name (DN) of the CMP requester. This is the
     *            subject of the first certificate in the extraCerts field of
     *            the CMP request or the sender extracted from the PKI message
     *            header. If neither signature-based protection was used nor the
     *            sender field was set the requesterDn is <code>null</code>.
     * @param pkcs10CertRequest
     *            the PKCS#10 certificate request received from a requester in
     *            a p10cr request. The PKCS#10 certificate request should be
     *            ASN.1 DER encoded.
     * @param requestedSubjectDn
     *            subject DN extracted from the CertTemplate of the request.
     *            This parameter is provided for convenience.
     *
     * @return <code>true</code> if the request is granted.
     */
    boolean checkP10CertRequest(byte[] transactionID, String requesterDn,
            byte[] pkcs10CertRequest, String requestedSubjectDn);

    /**
     * learn the enrollment status including any new certificate.
     * May respond false in case of internal processing error.
     * @param transactionID
     *            the transactionID of the CMP request/response message.
     *            The transactionID can be used to correlate calls of
     *            {@link #checkAndModifyCertRequest(byte[], String, byte[], String)},
     *            {@link #checkP10CertRequest(byte[], String, byte[], String)}
     *            and
     *            {@link #learnEnrollmentResult(byte[], byte[], String, String, String)}.
     * @param certificate
     *            the new certificate, which is assumed to be ASN.1 DER encoded,
     *            as returned by the CA. On enrollment failure,
     *            <code>null</code> is given.
     * @param serialNumber
     *            string representation of the certificate serial number.
     *            In case of enrollment failure, <code>null</code> is given.
     *            This parameter is provided for convenience.
     * @param subjectDN
     *            the subject Distinguished Name extracted from the certificate
     *            or from the certificate request in case of enrollment failure.
     *            This parameter is provided for convenience.
     * @param issuerDN
     *            the issuer Distinguished Name extracted from the certificate.
     *            In case of enrollment failure, <code>null</code> is given.
     *            This parameter is provided for convenience.
     *
     * @return true on success
     */
    boolean learnEnrollmentResult(byte[] transactionID, byte[] certificate,
            String serialNumber, String subjectDN, String issuerDN);

}
