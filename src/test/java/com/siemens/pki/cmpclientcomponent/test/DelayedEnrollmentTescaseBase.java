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
package com.siemens.pki.cmpclientcomponent.test;

import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TestUtils;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

public class DelayedEnrollmentTescaseBase extends DelayedDeliveryTestcaseBase {
    private SignatureValidationCredentials enrollmentCredentials;

    ClientContext getClientContext(final int enrollmentType) {
        final ClientContext clientContext = new ClientContext() {

            KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();

            @Override
            public EnrollmentContext getEnrollmentContext() {
                return new EnrollmentContext() {

                    @Override
                    public KeyPair getCertificateKeypair() {
                        return keyPair;
                    }

                    @Override
                    public VerificationContext getEnrollmentTrust() {
                        return enrollmentCredentials;
                    }

                    @Override
                    public int getEnrollmentType() {
                        return enrollmentType;
                    }

                    @Override
                    public List<TemplateExtension> getExtensions() {
                        return null;
                    }

                    @Override
                    public X509Certificate getOldCert() {
                        return null;
                    }

                    @Override
                    public boolean getRequestImplictConfirm() {
                        return false;
                    }

                    @Override
                    public String getSubject() {
                        return "CN=Subject";
                    }
                };
            }

            @Override
            public RevocationContext getRevocationContext() {
                fail("getRevocationContext");
                return null;
            }
        };
        return clientContext;
    }

    protected SignatureValidationCredentials getEnrollmentCredentials() throws Exception {
        if (enrollmentCredentials == null) {
            enrollmentCredentials = new SignatureValidationCredentials(
                    "credentials/ENROLL_Keystore.p12", TestUtils.PASSWORD_AS_CHAR_ARRAY);
        }
        return enrollmentCredentials;
    }
}
