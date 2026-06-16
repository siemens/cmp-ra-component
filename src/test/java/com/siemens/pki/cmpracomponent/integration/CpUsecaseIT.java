/*
 *  Copyright (c) 2026 Siemens AG
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
package com.siemens.pki.cmpracomponent.integration;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import com.siemens.pki.cmpracomponent.testutil.cert.CertificateAuthority;
import com.siemens.pki.cmpracomponent.testutil.cert.KeyAndCert;
import com.siemens.pki.cmpracomponent.testutil.cert.PkiHierarchyGenerator.FullPki;
import com.siemens.pki.cmpracomponent.testutil.cert.TestPkiStore;
import com.siemens.pki.cmpracomponent.testutil.profile.ExtensionProfiles;
import com.siemens.pki.cmpracomponent.testutil.req.CrmfAndCmpFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.junit.Test;

public class CpUsecaseIT {

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------
    private static final String INT_EE1_CN = "CN=ee01, O=Test INT, C=DE";
    private static final String INT_EE1_DNS = "ee01.int.test";

    // ---------------------------------------------------------------------
    // Signature-protected ir
    // ---------------------------------------------------------------------
    @Test
    public void eeCreatesCrmfAndSendsIrToRa_Signed() throws Exception {
        // Arrange
        final FullPki pki = TestPkiStore.get();

        // The existing EE keypair and cert are used to PROTECT the PKI message
        final PrivateKey signerKey = pki.intEe.privateKey();
        final X509Certificate signerCert = pki.intEe.certificate();
        final X500Name eeSender =
                new X500Name(signerCert.getSubjectX500Principal().getName());

        // New keypair for the *requested* certificate
        final KeyPair newKeys = CertificateAuthority.generateKeyPair();
        final X500Name newSubject = new X500Name(INT_EE1_CN);

        final GeneralName dnsName = new GeneralName(GeneralName.dNSName, INT_EE1_DNS);
        final Extensions requestedExts = ExtensionProfiles.eeTlsClientServer(List.of(dnsName));

        final CertificateRequestMessage crmf = CrmfAndCmpFactory.buildCrmfForEe(newKeys, newSubject, requestedExts);

        final X500Name raName = raSubjectDn();

        // Act
        final ProtectedPKIMessage ir =
                CrmfAndCmpFactory.buildCmpIrToRaSigned(crmf, eeSender, raName, signerKey, signerCert);

        final byte[] der = ir.toASN1Structure().getEncoded();

        // Assert (basic structural sanity)
        final GeneralPKIMessage parsed = new GeneralPKIMessage(der);

        assertThat(parsed.hasProtection(), is(true));
        assertThat(parsed.getBody().getType(), is(PKIBody.TYPE_INIT_REQ));

        // Signature protection adds the cert to extraCerts

        assertThat(parsed.toASN1Structure().getExtraCerts(), is(notNullValue()));
        assertThat(parsed.toASN1Structure().getExtraCerts().length, is(not(0)));
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------
    private static X500Name raSubjectDn() {
        final KeyAndCert ra = TestPkiStore.get().intRa;
        return new X500Name(ra.certificate().getSubjectX500Principal().getName());
    }
}
