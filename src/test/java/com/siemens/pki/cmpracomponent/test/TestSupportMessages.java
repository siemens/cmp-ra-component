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
package com.siemens.pki.cmpracomponent.test;

import static org.junit.Assert.*;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.test.framework.TestCertUtility;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.ByteArrayInputStream;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Time;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestSupportMessages extends CmpTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestSupportMessages.class);

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
        final Function<PKIMessage, PKIMessage> eeCmpClient = getEeClient();
        final ASN1ObjectIdentifier statusListOid = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.22");
        final ASN1ObjectIdentifier crlsOid = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.23");

        final PKIBody genmBody = new PKIBody(
                PKIBody.TYPE_GEN_MSG,
                new GenMsgContent(new InfoTypeAndValue(
                        statusListOid,
                        new DERSequence(new CRLStatus(
                                new CRLSource(
                                        null, new GeneralNames(new GeneralName(new X500Name("CN=distributionPoint")))),
                                new Time(new Date()))))));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("CrlUpdateRetrieval"),
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                genmBody);
        final PKIMessage genr = eeCmpClient.apply(genm);
        assertEquals("message type", PKIBody.TYPE_GEN_REP, genr.getBody().getType());
        final GenRepContent content = (GenRepContent) genr.getBody().getContent();
        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertEquals("number of itavs", 1, itav.length);
        assertEquals("crlsOid", crlsOid, itav[0].getInfoType());

        final ASN1Sequence sequenceOfCrl = (ASN1Sequence) itav[0].getInfoValue().toASN1Primitive();
        final CRL crl = CertificateFactory.getInstance("X.509")
                .generateCRL(new ByteArrayInputStream(
                        sequenceOfCrl.getObjectAt(0).toASN1Primitive().getEncoded()));
        assertNotNull("CRL", crl);
    }

    /*
     * Get CA certificates
     */
    @Test
    public void testGetCaCerts() throws Exception {
        final ASN1ObjectIdentifier getCaCertOid = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.17");
        final PKIBody genmBody =
                new PKIBody(PKIBody.TYPE_GEN_MSG, new GenMsgContent(new InfoTypeAndValue(getCaCertOid)));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("GetCaCertsCertProfile"),
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                genmBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("send" + MessageDumper.dumpPkiMessage(genm));
        }
        final PKIMessage genr = getEeClient().apply(genm);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("got" + MessageDumper.dumpPkiMessage(genr));
        }
        assertEquals("message type", PKIBody.TYPE_GEN_REP, genr.getBody().getType());
        final GenRepContent content = (GenRepContent) genr.getBody().getContent();
        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertEquals("number of itavs", 1, itav.length);
        assertEquals("getCaCertOid", getCaCertOid, itav[0].getInfoType());
        // id-it-caCerts OBJECT IDENTIFIER ::= {1 3 6 1 5 5 7 4 17}
        // CaCerts ::= SEQUENCE OF CMPCertificate
        // }
        final ASN1Sequence value = (ASN1Sequence) itav[0].getInfoValue();
        assertEquals("number of returned certificates", 20, value.size());
    }

    /*
     * Get CA certificates without transaction Id
     */
    @Test
    public void testGetCaCertsWithoutTransactionId() throws Exception {
        final ASN1ObjectIdentifier getCaCertOid = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.17");
        final PKIBody genmBody =
                new PKIBody(PKIBody.TYPE_GEN_MSG, new GenMsgContent(new InfoTypeAndValue(getCaCertOid)));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("GetCaCertsCertProfile") {
                    @Override
                    public ASN1OctetString getTransactionID() {
                        return null;
                    }
                },
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                genmBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("send" + MessageDumper.dumpPkiMessage(genm));
        }
        final PKIMessage genr = getEeClient().apply(genm);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("got" + MessageDumper.dumpPkiMessage(genr));
        }
        assertEquals("message type", PKIBody.TYPE_ERROR, genr.getBody().getType());
    }

    /*
     * Get Certificate Request Template
     */
    @Test
    public void testGetCertificateRequestTemplate() throws Exception {
        final Function<PKIMessage, PKIMessage> eeCmpClient = getEeClient();
        final ASN1ObjectIdentifier getCaCertOid = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.19");
        final PKIBody genmBody =
                new PKIBody(PKIBody.TYPE_GEN_MSG, new GenMsgContent(new InfoTypeAndValue(getCaCertOid)));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("GetCertificateRequestCertProfile"),
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                genmBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
            // enabled
            LOGGER.debug("send" + MessageDumper.dumpPkiMessage(genm));
        }
        final PKIMessage genr = eeCmpClient.apply(genm);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got" + MessageDumper.dumpPkiMessage(genr));
        }
        assertEquals("message type", PKIBody.TYPE_GEN_REP, genr.getBody().getType());
        final GenRepContent content = (GenRepContent) genr.getBody().getContent();
        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertEquals("number of itavs", 1, itav.length);
        assertEquals("getCaCertOid", getCaCertOid, itav[0].getInfoType());
        final CertReqTemplateContent crt = CertReqTemplateContent.getInstance(itav[0].getInfoValue());
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
        final ASN1ObjectIdentifier getCaCertOid = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.20");
        final PKIBody genmBody = new PKIBody(
                PKIBody.TYPE_GEN_MSG,
                new GenMsgContent(new InfoTypeAndValue(
                        getCaCertOid,
                        TestCertUtility.cmpCertificateFromCertificate(
                                TestCertUtility.loadCertificatesFromFile("credentials/CMP_EE_Root.pem")
                                        .get(0)))));
        final PKIMessage genm = PkiMessageGenerator.generateAndProtectMessage(
                new HeaderProviderForTest("GetRootCaKeyUpdate"),
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                genmBody);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("send" + MessageDumper.dumpPkiMessage(genm));
        }
        final PKIMessage genr = getEeClient().apply(genm);
        if (LOGGER.isDebugEnabled()) {
            // avoid unnecessary string processing, if debug isn't enabled
            LOGGER.debug("got" + MessageDumper.dumpPkiMessage(genr));
        }
        assertEquals("message type", PKIBody.TYPE_GEN_REP, genr.getBody().getType());
        final GenRepContent content = (GenRepContent) genr.getBody().getContent();
        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertEquals("number of itavs", 1, itav.length);
        assertEquals("rootCaKeyUpdate", new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.18"), itav[0].getInfoType());
        final ASN1Sequence value = (ASN1Sequence) itav[0].getInfoValue();
        assertNotNull("parse RootCaKeyUpdateContent", RootCaKeyUpdateContent.getInstance(value));
    }
}
