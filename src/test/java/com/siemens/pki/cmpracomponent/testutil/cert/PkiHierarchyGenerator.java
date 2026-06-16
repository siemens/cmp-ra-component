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
package com.siemens.pki.cmpracomponent.testutil.cert;

import com.siemens.pki.cmpracomponent.testutil.cert.CertificateAuthority.IssueParams;
import java.util.List;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;

public class PkiHierarchyGenerator {

    public static class FullPki {
        // INT domain
        public KeyAndCert intRoot;
        public KeyAndCert intIca;
        public KeyAndCert intEe;
        public KeyAndCert intRa;
        public KeyAndCert intCa;

        // EXT-EE domain
        public KeyAndCert extEeRoot;
        public KeyAndCert extEeIca;
        public KeyAndCert extEeEe;

        // EXT-CA domain
        public KeyAndCert extCaRoot;
        public KeyAndCert extCaIca;
        public KeyAndCert extCaCa;
    }

    public FullPki generate() throws Exception {
        FullPki pki = new FullPki();

        // ================= INT =================
        var intRootKeys = CertificateAuthority.generateKeyPair();
        var intRootCert = CertificateAuthority.selfSignedRoot(intRootKeys, "CN=INT-ROOT", /* pathLen */ 1);
        pki.intRoot = new KeyAndCert(intRootKeys.getPrivate(), intRootCert);

        var intIcaKeys = CertificateAuthority.generateKeyPair();
        var intIcaParams = new IssueParams();
        intIcaParams.isCA = true;
        intIcaParams.pathLenConstraint = 0; // ICA can issue only leaves
        var intIcaCert = CertificateAuthority.issueCertificate(
                intIcaKeys, intRootCert, intRootKeys.getPrivate(), "CN=INT-ICA", intIcaParams);
        pki.intIca = new KeyAndCert(intIcaKeys.getPrivate(), intIcaCert);

        // INT End Entity (server+client TLS), with SANs
        pki.intEe = issueLeaf(
                "INT-EE",
                pki.intIca,
                List.of(
                        CertificateAuthority.dns("int-ee.test"),
                        CertificateAuthority.dns("ee.internal"),
                        CertificateAuthority.ip("10.0.0.10")),
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth});

        // INT RA (typically signs/validates requests) – give clientAuth EKU
        pki.intRa =
                issueLeaf("INT-RA", pki.intIca, List.of(CertificateAuthority.dns("int-ra.test")), new KeyPurposeId[] {
                    KeyPurposeId.id_kp_clientAuth
                });

        // INT CA (a leaf CA used by tests; CA=true)
        var intCaKeys = CertificateAuthority.generateKeyPair();
        var intCaParams = new IssueParams();
        intCaParams.isCA = true;
        intCaParams.pathLenConstraint = 0;
        var intCaCert = CertificateAuthority.issueCertificate(
                intCaKeys, intIcaCert, intIcaKeys.getPrivate(), "CN=INT-CA", intCaParams);
        pki.intCa = new KeyAndCert(intCaKeys.getPrivate(), intCaCert);

        // ================= EXT-EE =================
        var extEeRootKeys = CertificateAuthority.generateKeyPair();
        var extEeRootCert = CertificateAuthority.selfSignedRoot(extEeRootKeys, "CN=EXT-EE-ROOT", 1);
        pki.extEeRoot = new KeyAndCert(extEeRootKeys.getPrivate(), extEeRootCert);

        var extEeIcaKeys = CertificateAuthority.generateKeyPair();
        var extEeIcaParams = new IssueParams();
        extEeIcaParams.isCA = true;
        extEeIcaParams.pathLenConstraint = 0;
        var extEeIcaCert = CertificateAuthority.issueCertificate(
                extEeIcaKeys, extEeRootCert, extEeRootKeys.getPrivate(), "CN=EXT-EE-ICA", extEeIcaParams);
        pki.extEeIca = new KeyAndCert(extEeIcaKeys.getPrivate(), extEeIcaCert);

        pki.extEeEe = issueLeaf(
                "EXT-EE-EE",
                new KeyAndCert(extEeIcaKeys.getPrivate(), extEeIcaCert),
                List.of(CertificateAuthority.dns("ext-ee.example.com")),
                new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth});

        // ================= EXT-CA =================
        var extCaRootKeys = CertificateAuthority.generateKeyPair();
        var extCaRootCert = CertificateAuthority.selfSignedRoot(extCaRootKeys, "CN=EXT-CA-ROOT", 1);
        pki.extCaRoot = new KeyAndCert(extCaRootKeys.getPrivate(), extCaRootCert);

        var extCaIcaKeys = CertificateAuthority.generateKeyPair();
        var extCaIcaParams = new IssueParams();
        extCaIcaParams.isCA = true;
        extCaIcaParams.pathLenConstraint = 0;
        var extCaIcaCert = CertificateAuthority.issueCertificate(
                extCaIcaKeys, extCaRootCert, extCaRootKeys.getPrivate(), "CN=EXT-CA-ICA", extCaIcaParams);
        pki.extCaIca = new KeyAndCert(extCaIcaKeys.getPrivate(), extCaIcaCert);

        // A leaf CA under EXT-CA (CA=true)
        var extCaCaKeys = CertificateAuthority.generateKeyPair();
        var extCaCaParams = new IssueParams();
        extCaCaParams.isCA = true;
        extCaCaParams.pathLenConstraint = 0;
        var extCaCaCert = CertificateAuthority.issueCertificate(
                extCaCaKeys, extCaIcaCert, extCaIcaKeys.getPrivate(), "CN=EXT-CA-CA", extCaCaParams);
        pki.extCaCa = new KeyAndCert(extCaCaKeys.getPrivate(), extCaCaCert);

        return pki;
    }

    private KeyAndCert issueLeaf(String cn, KeyAndCert issuer, List<GeneralName> sans, KeyPurposeId[] ekus)
            throws Exception {
        var keys = CertificateAuthority.generateKeyPair();
        var p = new IssueParams();
        p.isCA = false;
        p.extendedKeyUsages = ekus;
        p.subjectAltNames = CertificateAuthority.toGeneralNames(sans);
        var cert =
                CertificateAuthority.issueCertificate(keys, issuer.certificate(), issuer.privateKey(), "CN=" + cn, p);
        return new KeyAndCert(keys.getPrivate(), cert);
    }
}
