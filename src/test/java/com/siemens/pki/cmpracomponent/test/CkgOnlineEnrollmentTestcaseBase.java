/*
 *  Copyright (c) 2021 Siemens AG
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.siemens.pki.cmpracomponent.cryptoservices.CmsDecryptor;
import com.siemens.pki.cmpracomponent.cryptoservices.DataSignVerifier;
import com.siemens.pki.cmpracomponent.cryptoservices.DataSigner;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.EnrollmentResult;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TestCertUtility;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CkgOnlineEnrollmentTestcaseBase extends OnlineEnrollmentTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(CkgOnlineEnrollmentTestcaseBase.class);

    public static final String INTERFACE_NAME = "testclient";

    protected DataSignVerifier verifier;

    public EnrollmentResult executeCrmfCertificateRequestWithoutKey(
            final int requestMesssageType,
            final int expectedResponseMessageType,
            final ProtectionProvider protectionProvider,
            final Function<PKIMessage, PKIMessage> cmpClient,
            final CmsDecryptor decryptor)
            throws Exception {
        // grab the key parameters from a real public key
        final KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();
        final SubjectPublicKeyInfo subjectPublicKey =
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        final byte[] publicKey = {};
        final CertTemplateBuilder ctb = new CertTemplateBuilder()
                .setPublicKey(new SubjectPublicKeyInfo(subjectPublicKey.getAlgorithm(), publicKey))
                .setSubject(new X500Name("CN=Subject"));

        final CertTemplate template = ctb.build();
        CertTemplate.getInstance(template.getEncoded(ASN1Encoding.DER));
        final PKIBody crBody = PkiMessageGenerator.generateIrCrKurBody(requestMesssageType, template, null, null);

        final PKIMessage cr = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(3, "CkgOnlineEnrollment"), protectionProvider, crBody);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(cr));
        }
        final PKIMessage crResponse = cmpClient.apply(cr);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(crResponse));
        }
        assertEquals(
                "message type",
                expectedResponseMessageType,
                crResponse.getBody().getType());

        final CertResponse certResponse = ((CertRepMessage) crResponse.getBody().getContent()).getResponse()[0];
        assertNull("failinfo in response", certResponse.getStatus().getFailInfo());
        final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
        final CMPCertificate enrolledCertificate =
                certifiedKeyPair.getCertOrEncCert().getCertificate();
        // recover private key
        final PrivateKey recoveredKey = verifier.verifySignedKey(decryptor.decrypt(
                EnvelopedData.getInstance(certifiedKeyPair.getPrivateKey().getValue())));
        assertNotNull(recoveredKey);

        final PKIMessage certConf = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest(crResponse.getHeader()),
                protectionProvider,
                PkiMessageGenerator.generateCertConfBody(enrolledCertificate));

        // try to use received certificate and key
        final DataSigner testSigner = new DataSigner(
                recoveredKey, TestCertUtility.certificateFromCmpCertificate(enrolledCertificate), INTERFACE_NAME);
        final byte[] msgToSign = "Hello Signer, I am the message".getBytes();
        assertArrayEquals(
                msgToSign,
                DataSignVerifier.verifySignature(testSigner.signData(msgToSign).getEncoded()));

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send:\n" + MessageDumper.dumpPkiMessage(certConf));
        }
        final PKIMessage pkiConf = cmpClient.apply(certConf);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(pkiConf));
        }
        assertEquals("message type", PKIBody.TYPE_CONFIRM, pkiConf.getBody().getType());

        return new EnrollmentResult(enrolledCertificate, keyPair.getPrivate());
    }

    @Before
    public void setUp() throws Exception {
        verifier = new DataSignVerifier(
                new SignatureValidationCredentials("credentials/CMP_LRA_DOWNSTREAM_Root.pem", null), INTERFACE_NAME);
    }
}
