/*
 * Copyright (c) 2022 Siemens AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.siemens.pki.cmpracomponent.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.MacProtection;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.security.KeyPair;
import java.util.function.Function;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestSignatureBasedCrWithSuppress extends SignatureEnrollmentWithSuppressTestcase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestSignatureBasedCrWithSuppress.class);

    /**
     * Enrolling an End Entity to a Known PKI/
     *
     * @throws Exception
     */
    @Test
    public void testCrWithSuppress() throws Exception {

        final int requestMesssageType = PKIBody.TYPE_CERT_REQ;
        final int expectedResponseMessageType = PKIBody.TYPE_CERT_REP;
        final ProtectionProvider protectionProvider = ConfigurationFactory.getEeSignaturebasedProtectionProvider();
        final Function<PKIMessage, PKIMessage> cmpClient = getEeClient();
        boolean isSuppressRedundantExtraCerts = true;

        final KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(
                        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(new X500Name("CN=Subject"));

        final PKIBody crBody =
                PkiMessageGenerator.generateIrCrKurBody(requestMesssageType, ctb.build(), null, keyPair.getPrivate());

        final PKIMessage cr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("theCertProfileForOnlineEnrollment"), protectionProvider, crBody);

        // === NEW ASSERTIONS ===
        assertNotNull("CR message must not be null", cr);
        assertNotNull("CR header must not be null", cr.getHeader());
        assertNotNull("CR transaction ID must not be null", cr.getHeader().getTransactionID());
        byte[] transactionId = cr.getHeader().getTransactionID().getOctets();

        if (isSuppressRedundantExtraCerts) {
            assertNotNull("CR should contain extraCerts initially", cr.getExtraCerts());
            assertTrue("CR extraCerts must contain at least one certificate", cr.getExtraCerts().length > 0);
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }

        final PKIMessage crResponse = cmpClient.apply(cr);

        // === NEW ASSERTIONS ===
        assertNotNull("CR response must not be null", crResponse);
        assertNotNull("CR response header must not be null", crResponse.getHeader());
        assertNotNull(
                "CR response transaction ID must not be null",
                crResponse.getHeader().getTransactionID());

        // Transaction ID continuity
        assertArrayEquals(
                "Transaction ID must remain constant",
                transactionId,
                crResponse.getHeader().getTransactionID().getOctets());

        System.out.println("CP Details: ");
        System.out.println("Transaction id: " + crResponse.getHeader().getTransactionID());

        if (isSuppressRedundantExtraCerts) {
            assertNotNull("CP should contain extraCerts", crResponse.getExtraCerts());
            assertTrue("CP extraCerts must contain at least one certificate", crResponse.getExtraCerts().length > 0);
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }

        assertEquals(
                "message type",
                expectedResponseMessageType,
                crResponse.getBody().getType());

        if (protectionProvider instanceof MacProtection) {
            assertEquals(
                    "protection type",
                    cr.getHeader().getProtectionAlg().getAlgorithm().getId(),
                    crResponse.getHeader().getProtectionAlg().getAlgorithm().getId());
        }

        final CertRepMessage certRep = (CertRepMessage) crResponse.getBody().getContent();

        // === NEW ASSERTIONS ===
        assertNotNull("CertRep content must not be null", certRep);
        assertTrue("CertRep must contain at least one response", certRep.getResponse().length > 0);
        assertNotNull("CertifiedKeyPair must not be null", certRep.getResponse()[0].getCertifiedKeyPair());

        final CMPCertificate enrolledCertificate = certRep.getResponse()[0]
                .getCertifiedKeyPair()
                .getCertOrEncCert()
                .getCertificate();

        assertNotNull("Enrolled certificate must not be null", enrolledCertificate);

        final PKIMessage certConf = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(crResponse.getHeader()),
                protectionProvider,
                PkiMessageGenerator.generateCertConfBody(enrolledCertificate));

        // === NEW ASSERTIONS ===
        assertNotNull("CertConf must not be null", certConf);
        assertNotNull("CertConf header must not be null", certConf.getHeader());
        assertArrayEquals(
                "Transaction ID must remain constant across CR → CP → CertConf",
                transactionId,
                certConf.getHeader().getTransactionID().getOctets());

        if (isSuppressRedundantExtraCerts) {
            assertNotNull("CertConf should contain extraCerts", certConf.getExtraCerts());
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
        }

        final PKIMessage pkiConf = cmpClient.apply(certConf);

        // === NEW ASSERTIONS ===
        assertNotNull("PKIConf must not be null", pkiConf);
        assertNotNull("PKIConf header must not be null", pkiConf.getHeader());
        assertArrayEquals(
                "Transaction ID must remain constant across all messages",
                transactionId,
                pkiConf.getHeader().getTransactionID().getOctets());

        if (isSuppressRedundantExtraCerts) {
            assertNull("PKIConf must not contain redundant extraCerts", pkiConf.getExtraCerts());
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
        }

        assertEquals("message type", PKIBody.TYPE_CONFIRM, pkiConf.getBody().getType());
    }
}
