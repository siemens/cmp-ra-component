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
package com.siemens.pki.cmpracomponent.test;

import static org.junit.Assert.assertEquals;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.EnrollmentResult;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.security.KeyPair;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestSignaturebasedKur extends SignatureEnrollmentTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestSignaturebasedKur.class);

    /**
     * Updating a Valid Certificate
     *
     * @throws Exception
     */
    @Test
    public void testKur() throws Exception {
        final EnrollmentResult certificateToUpdate = executeCrmfCertificateRequest(
                PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                getEeClient());
        final ProtectionProvider kurProtector = getEnrollmentCredentials()
                .setEndEntityToProtect(certificateToUpdate.getCertificate(), certificateToUpdate.getPrivateKey());
        final KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();
        final Certificate x509v3pkCertToUpdate =
                certificateToUpdate.getCertificate().getX509v3PKCert();
        final X500Name issuer = x509v3pkCertToUpdate.getIssuer();
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(
                        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(x509v3pkCertToUpdate.getSubject())
                .setIssuer(issuer);
        final Controls controls = new Controls(new AttributeTypeAndValue(
                CMPObjectIdentifiers.regCtrl_oldCertID,
                new CertId(new GeneralName(issuer), x509v3pkCertToUpdate.getSerialNumber())));

        final PKIBody kurBody = PkiMessageGenerator.generateIrCrKurBody(
                PKIBody.TYPE_KEY_UPDATE_REQ, ctb.build(), controls, keyPair.getPrivate());
        final PKIMessage kur = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("certProfileForKur"), kurProtector, kurBody);

        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(kur));
        }
        final PKIMessage kurResponse = getEeClient().apply(kur);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(kurResponse));
        }
        assertEquals(
                "message type",
                PKIBody.TYPE_KEY_UPDATE_REP,
                kurResponse.getBody().getType());

        final CMPCertificate enrolledCertificate = ((CertRepMessage)
                        kurResponse.getBody().getContent())
                .getResponse()[0]
                .getCertifiedKeyPair()
                .getCertOrEncCert()
                .getCertificate();

        final PKIMessage certConf = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(kurResponse.getHeader()),
                kurProtector,
                PkiMessageGenerator.generateCertConfBody(enrolledCertificate));

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
        }
        final PKIMessage pkiConf = getEeClient().apply(certConf);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
        }
        assertEquals("message type", PKIBody.TYPE_CONFIRM, pkiConf.getBody().getType());
    }
}
