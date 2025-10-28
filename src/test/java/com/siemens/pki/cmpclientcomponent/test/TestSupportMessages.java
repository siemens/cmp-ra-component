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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.configuration.EnrollmentContext;
import com.siemens.pki.cmpclientcomponent.configuration.RevocationContext;
import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler.RootCaCertificateUpdateResponse;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.TestCertUtility;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertReqTemplateContent;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.Controls;
import org.junit.Before;
import org.junit.Test;

public class TestSupportMessages extends CmpClientTestcaseBase {

    private static final String UPSTREAM_TRUST_PATH = "credentials/CMP_LRA_DOWNSTREAM_Root.pem";
    private static final ClientContext clientContext = new ClientContext() {

        @Override
        public EnrollmentContext getEnrollmentContext() {
            fail("getEnrollmentContext");
            return null;
        }

        @Override
        public RevocationContext getRevocationContext() {
            fail("getRevocationContext");
            return null;
        }
    };

    @Before
    public void setUp() throws Exception {
        // there should be no CA in charge
        launchCmpRa(ConfigurationFactory.buildSignatureBasedDownstreamOnlyConfiguration(), (x, y, z) -> {
            fail();
            return null;
        });
    }

    /**
     * CRL Update Retrieval
     *
     * @throws Exception
     */
    @Test
    public void testCrlUpdateRetrieval() throws Exception {
        final List<X509CRL> crls = getSignatureBasedCmpClient("TestSupportMessages", clientContext, UPSTREAM_TRUST_PATH)
                .getCrls(null, null, new String[] {"CN=distributionPoint"}, new Date());
        assertNotNull("CRL", crls);
    }

    /*
     * Get CA certificates
     */
    @Test
    public void testGetCaCerts() throws Exception {
        final List<X509Certificate> certs = getSignatureBasedCmpClient(
                        "TestSupportMessages", clientContext, UPSTREAM_TRUST_PATH)
                .getCaCertificates();
        assertEquals("number of returned certificates", 20, certs.size());
    }

    /*
     * Get Certificate Request Template
     */
    @Test
    public void testGetCertificateRequestTemplate() throws Exception {
        final byte[] template = getSignatureBasedCmpClient("TestSupportMessages", clientContext, UPSTREAM_TRUST_PATH)
                .getCertificateRequestTemplate();
        final CertReqTemplateContent crt = CertReqTemplateContent.getInstance(template);
        assertNotNull("parse CertTemplate", crt.getCertTemplate());
        final AttributeTypeAndValue[] controls =
                Controls.getInstance(crt.getKeySpec()).toAttributeTypeAndValueArray();

        assertEquals(CMPObjectIdentifiers.id_regCtrl_rsaKeyLen, controls[0].getType());

        assertNotNull("parse INTEGER", ASN1Integer.getInstance(controls[0].getValue()));
    }

    /*
     * Get Root CA Certificate Update
     */
    @Test
    public void testGetRootCaCertificateUpdate() throws Exception {
        final RootCaCertificateUpdateResponse update = getSignatureBasedCmpClient(
                        "TestSupportMessages", clientContext, UPSTREAM_TRUST_PATH)
                .getRootCaCertificateUpdate(TestCertUtility.loadCertificatesFromFile("credentials/CMP_EE_Root.pem")
                        .get(0));
        assertNotNull(update.getNewWithNew());
        assertNotNull(update.getNewWithOld());
        assertNotNull(update.getOldWithNew());
    }
}
