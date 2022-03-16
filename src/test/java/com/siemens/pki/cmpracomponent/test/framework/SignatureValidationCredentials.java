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
package com.siemens.pki.cmpracomponent.test.framework;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;

public class SignatureValidationCredentials implements VerificationContext {

    private final Set<X509Certificate> trust = new HashSet<>();
    private final Set<X509Certificate> intermeditateCertificates =
            new HashSet<>();

    public SignatureValidationCredentials(final String keyStoreFileName,
            final char[] password) {
        Set<X509Certificate> trustedCertificates;
        try {
            trustedCertificates = TestCertUtility.loadCertificatesFromKeystore(
                    TestCertUtility.loadTruststoreFromFile(keyStoreFileName,
                            password));
            for (final X509Certificate aktCert : trustedCertificates) {
                if (TestCertUtility.isSelfSigned(aktCert)) {
                    trust.add(aktCert);
                } else {
                    intermeditateCertificates.add(aktCert);
                }
            }
        } catch (final Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public Collection<X509Certificate> getAdditionalCerts() {
        return intermeditateCertificates;
    }

    @Override
    public Collection<X509Certificate> getTrustedCertificates() {
        return trust;
    }

}
