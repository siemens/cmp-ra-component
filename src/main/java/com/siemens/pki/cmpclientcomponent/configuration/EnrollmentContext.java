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
package com.siemens.pki.cmpclientcomponent.configuration;

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.cmp.PKIBody;

/**
 * enrollment specific configuration
 *
 */
public interface EnrollmentContext {

    /**
     * extension used for template
     */
    interface TemplateExtension {
        /**
         * Gets the extensions's object identifier.
         *
         * @return the object identifier as a String
         */
        String getId();

        /**
         * Gets the extensions's DER-encoded value. Note, this is the bytes that are
         * encoded as an OCTET STRING. It does not include the OCTET STRING tag and
         * length.
         *
         * @return a copy of the extension's value, or {@code null} if no extension
         *         value is present.
         */
        byte[] getValue();

        /**
         * Gets the extension's criticality setting.
         *
         * @return true if this is a critical extension.
         */
        boolean isCritical();
    }

    /**
     * key pair for the new certificate; is is used for signature-based POPO, and
     * the corresponding public key is put in the certificate template. Is not
     * required if message body type is 4(p10cr).
     *
     * @return key pair or <code>null</code> if central key generation should be
     *         requested
     */
    KeyPair getCertificateKeypair();

    /**
     * p10cr CertificationRequest message body. Ignored if message body type is not
     * 4(p10cr).
     *
     * @return the p10cr CertificationRequest message body or <code>null</code>.
     */
    default byte[] getCertificationRequest() {
        return null;
    }

    /**
     * provide VerificationContext used to validate the newly enrolled certificate
     * and build the enrollment chain
     *
     * @return an VerificationContext related to the enrolled certificate
     */
    VerificationContext getEnrollmentTrust();

    /**
     * initial enrollment message type 0(ir), 2(cr), 7(kur) or 4(p10cr)
     *
     * @return initial enrollment message body type
     */
    default int getEnrollmentType() {
        return PKIBody.TYPE_CERT_REQ;
    }

    /**
     * extensions to be added to the CRMF template. Ignored if message body type is
     * 4(p10cr).
     *
     * @return list of extensions or <code>null</code> if extensions should taken
     *         from {@link #getOldCert()} or absent
     */
    List<TemplateExtension> getExtensions();

    /**
     * a KUR contains a id-regCtrl-oldCertID control holding issuer and serialNumber
     * of the certificate to be updated. Here an old certificate can be provided.
     * Ignored if message body type is 4(p10cr).
     *
     * @return certificate to be updated or <code>null</code> if the control
     *         id-regCtrl-oldCertID should'nt be used.
     */
    X509Certificate getOldCert();

    /**
     * control implicit confirmation for enrolled certificates
     *
     * @return true, if end entity requests implicit confirmation
     */
    boolean getRequestImplictConfirm();

    /**
     * subject to be inserted in the CRMF template or <code>null</code> if subject
     * should taken from {@link #getOldCert()} or absent. Ignored if message body
     * type is 4(p10cr).
     *
     * @return the subject or <code>null</code>
     */
    String getSubject();
}
