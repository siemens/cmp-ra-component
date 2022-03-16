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

import java.net.URI;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;

/**
 * an instance of an {@link VerificationContext} provides all attributes
 * required to verify external credentials.
 * For technical background have a look to the
 * <a href=
 * "https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html">Java
 * PKI Programmer's Guide</a>. The {@link VerificationContext} is internally
 * used to set up an PKIX {@link CertPathBuilder} for certificate chain
 * validation
 *
 */
public interface VerificationContext {

    /**
     * optionally provide additional intermediate certificates which can be used
     * for
     * certificate chain building
     *
     * @return intermediate certificates useful for chain building in context
     *         of validation or <code>null</code>
     */
    default Collection<X509Certificate> getAdditionalCerts() {
        return Collections.emptyList();
    }

    /**
     * optionally provide additional Certificate Revocation Lists used for
     * verification as governed by {@link #getPKIXRevocationCheckerOptions()}
     *
     * @return CRLs used in validation procedure or <code>null</code>
     */
    default Collection<X509CRL> getCRLs() {
        return Collections.emptyList();
    }

    /**
     * optionally provide the location of the OCSP responder used for
     * verification as governed by {@link #getPKIXRevocationCheckerOptions()}.
     *
     * @return OCSP responder location or <code>null</code>
     */
    default URI getOCSPResponder() {
        return null;
    }

    /**
     * optionally provide options to control the revocation checking mechanism.
     * For details
     * see {@link PKIXRevocationChecker.Option}.
     *
     * @return revocation checking options or <code>null</code>
     */
    default EnumSet<PKIXRevocationChecker.Option> getPKIXRevocationCheckerOptions() {
        return null;
    }

    /**
     * provide a shared secret if trust validation based on a shared secret
     * should be supported for the given client senderKID
     *
     * @param senderKID
     *            identifies the key material used for
     *            verifying the message protection if available,
     *            <code>null</code> otherwise.
     *
     * @return a trusted shared secret or <code>null</code> if no shared secret
     *         verification should be used for this sender
     */
    default byte[] getSharedSecret(final byte[] senderKID) {
        return null;
    }

    /**
     * provide all trusted certificates if signature-based trust validation
     * should be supported
     *
     * @return the trusted certificates used in the validation procedure or
     *         <code>null</code> if no certificate based verification should be
     *         used.
     */
    default Collection<X509Certificate> getTrustedCertificates() {
        return Collections.emptyList();
    }

    /**
     * control use of the Authority Information Access (AIA) certificate
     * extension
     *
     * @return <code>true</code> if AIA entries should be used
     */
    default boolean isAIAsEnabled() {
        return false;
    }

    /**
     * control use of the for the CRL Distribution Points (CDP) certificate
     * extension
     *
     * @return <code>true</code> if CDP entries should be used
     */
    default boolean isCDPsEnabled() {
        return false;
    }

    /**
     * additional check for intermediate certificates in chain. This method is
     * called for each intermediate certificate after chain building.
     *
     * @param cert
     *            the certificate to check
     *
     * @return <code>true</code> if the certificate is acceptable
     *
     */
    default boolean isIntermediateCertAcceptable(final X509Certificate cert) {
        return true;
    }

    /**
     * additional check for leaf certificate in chain
     *
     * @param cert
     *            the certificate to check
     * @return <code>true</code> if the certificate is acceptable
     */
    default boolean isLeafCertAcceptable(final X509Certificate cert) {
        return true;
    }
}
