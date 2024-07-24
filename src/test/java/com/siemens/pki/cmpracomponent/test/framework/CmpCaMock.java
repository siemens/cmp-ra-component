/*
 *  Copyright (c) 2020 Siemens AG
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

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;
import static org.junit.Assert.assertTrue;

import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.protection.SignatureBasedProtection;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a mocked Certificate Authority
 */
public class CmpCaMock implements CmpRaComponent.UpstreamExchange {

    private static final String INTERFACE_NAME = "CA Mock";
    private static final Logger LOGGER = LoggerFactory.getLogger(CmpCaMock.class);
    private static final JcaX509ContentVerifierProviderBuilder X509_CVPB =
            new JcaX509ContentVerifierProviderBuilder().setProvider(CertUtility.getBouncyCastleProvider());
    private static final JcaPEMKeyConverter JCA_KEY_CONVERTER = new JcaPEMKeyConverter();
    private static final int MAX_LAST_RECEIVED = 10;

    private final LinkedList<PKIMessage> lastReceivedMessages = new LinkedList<>();

    private final ProtectionProvider caProtectionProvider;

    private final SignatureCredentialContext enrollmentCredentials;

    public CmpCaMock(final String enrollmentCredentials, final String protectionCredentials) throws Exception {
        this.enrollmentCredentials =
                new TrustChainAndPrivateKey(enrollmentCredentials, TestUtils.PASSWORD_AS_CHAR_ARRAY);
        caProtectionProvider = new SignatureBasedProtection(
                new TrustChainAndPrivateKey(protectionCredentials, TestUtils.PASSWORD_AS_CHAR_ARRAY), INTERFACE_NAME);
    }

    private CMPCertificate createCertificate(
            final X500Name subject,
            final SubjectPublicKeyInfo publicKey,
            final X509Certificate issuingCert,
            Extensions extensionsFromTemplate)
            throws PEMException, NoSuchAlgorithmException, CertIOException, CertificateException,
                    OperatorCreationException {
        final long now = System.currentTimeMillis();
        final PublicKey pubKey = JCA_KEY_CONVERTER.getPublicKey(publicKey);
        final X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                issuingCert.getSubjectX500Principal(),
                BigInteger.valueOf(now),
                new Date(now - 60 * 60 * 1000L),
                new Date(now + 100 * 60 * 60 * 1000L),
                new X500Principal(subject.toString()),
                pubKey);

        final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        if (extensionsFromTemplate != null) {
            Arrays.stream(extensionsFromTemplate.getExtensionOIDs()).forEach(oid -> {
                try {
                    v3CertBldr.addExtension(extensionsFromTemplate.getExtension(oid));
                } catch (final CertIOException e) {
                    e.printStackTrace();
                }
            });
        }
        v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
        v3CertBldr.addExtension(
                Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuingCert));
        v3CertBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(
                        AlgorithmHelper.getSigningAlgNameFromKey(enrollmentCredentials.getPrivateKey()))
                .setProvider(TestCertUtility.BOUNCY_CASTLE_PROVIDER);

        return TestCertUtility.cmpCertificateFromCertificate(new JcaX509CertificateConverter()
                .setProvider(TestCertUtility.BOUNCY_CASTLE_PROVIDER)
                .getCertificate(v3CertBldr.build(signerBuilder.build(enrollmentCredentials.getPrivateKey()))));
    }

    private PKIMessage generateError(final PKIMessage receivedMessage, final String errorDetails) throws Exception {
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                PkiMessageGenerator.generateErrorBody(PKIFailureInfo.badRequest, errorDetails));
    }

    public PKIMessage getLastReceivedRequest() {
        return lastReceivedMessages.getFirst();
    }

    public PKIMessage getReceivedRequestAt(int index) {
        return lastReceivedMessages.get(index);
    }

    private PKIMessage handleCertConfirm(final PKIMessage receivedMessage) throws Exception {
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                PkiMessageGenerator.generatePkiConfirmBody());
    }

    private PKIMessage handleCrmfCerticateRequest(final PKIMessage receivedMessage) throws Exception {
        // get copy of enrollment chain
        final List<X509Certificate> issuingChain = enrollmentCredentials.getCertificateChain();

        final X509Certificate issuingCert = issuingChain.get(0);
        final CertTemplate requestTemplate = ((CertReqMessages)
                        receivedMessage.getBody().getContent())
                .toCertReqMsgArray()[0]
                .getCertReq()
                .getCertTemplate();
        final SubjectPublicKeyInfo publicKey = requestTemplate.getPublicKey();
        final X500Name subject = requestTemplate.getSubject();
        final CMPCertificate cmpCertificateFromCertificate =
                createCertificate(subject, publicKey, issuingCert, requestTemplate.getExtensions());

        // drop root certificate from copy
        issuingChain.remove(issuingChain.size() - 1);
        final List<CMPCertificate> issuingChainForExtraCerts = new ArrayList<>(issuingChain.size());
        for (final X509Certificate aktCert : issuingChain) {
            issuingChainForExtraCerts.add(TestCertUtility.cmpCertificateFromCertificate(aktCert));
        }
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                null,
                PkiMessageGenerator.generateIpCpKupBody(
                        receivedMessage.getBody().getType() + 1, cmpCertificateFromCertificate),
                issuingChainForExtraCerts);
    }

    CMPCertificate handleP10CerticateRequest(final PKCS10CertificationRequest certificationRequest) throws Exception {
        // get copy of enrollment chain
        final List<X509Certificate> issuingChain = enrollmentCredentials.getCertificateChain();
        final X509Certificate issuingCert = issuingChain.get(0);
        return createCertificate(
                certificationRequest.getSubject(),
                certificationRequest.getSubjectPublicKeyInfo(),
                issuingCert,
                certificationRequest.getRequestedExtensions());
    }

    private PKIMessage handleP10CerticateRequest(final PKIMessage receivedMessage) throws Exception {
        // get copy of enrollment chain
        final List<X509Certificate> issuingChain = enrollmentCredentials.getCertificateChain();

        final X509Certificate issuingCert = issuingChain.get(0);
        final CertificationRequestInfo certificationRequestInfo =
                ((CertificationRequest) receivedMessage.getBody().getContent()).getCertificationRequestInfo();
        final CMPCertificate cmpCertificateFromCertificate = createCertificate(
                certificationRequestInfo.getSubject(),
                certificationRequestInfo.getSubjectPublicKeyInfo(),
                issuingCert,
                null);

        // drop root certificate from copy
        issuingChain.remove(issuingChain.size() - 1);
        final List<CMPCertificate> issuingChainForExtraCerts = new ArrayList<>(issuingChain.size());
        for (final X509Certificate aktCert : issuingChain) {
            issuingChainForExtraCerts.add(TestCertUtility.cmpCertificateFromCertificate(aktCert));
        }
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                null,
                PkiMessageGenerator.generateIpCpKupBody(PKIBody.TYPE_CERT_REP, cmpCertificateFromCertificate),
                issuingChainForExtraCerts);
    }

    private PKIMessage handleRevocationRequest(final PKIMessage receivedMessage) throws Exception {
        final RevRepContentBuilder rrcb = new RevRepContentBuilder();
        rrcb.add(new PKIStatusInfo(PKIStatus.granted));
        return PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(receivedMessage),
                caProtectionProvider,
                new PKIBody(PKIBody.TYPE_REVOCATION_REP, rrcb.build()));
    }

    public byte[] processP10CerticateRequest(final byte[] csr, final String certProfile) {
        try {
            final PKCS10CertificationRequest p10Request = new PKCS10CertificationRequest(csr);
            if (!p10Request.isSignatureValid(X509_CVPB.build(p10Request.getSubjectPublicKeyInfo()))) {
                LOGGER.error("invalid P10 Request");
                return null;
            }
            return ifNotNull(handleP10CerticateRequest(p10Request), CMPCertificate::getEncoded);
        } catch (final Exception e) {
            LOGGER.error("P10 processing error", e);
            return null;
        }
    }

    @Override
    public byte[] sendReceiveMessage(
            final byte[] rawReceivedMessage, final String certProfile, final int bodyTypeOfFirstRequest) {
        assertTrue(
                "request message type",
                Arrays.asList(
                                PKIBody.TYPE_INIT_REQ,
                                PKIBody.TYPE_CERT_REQ,
                                PKIBody.TYPE_KEY_UPDATE_REQ,
                                PKIBody.TYPE_REVOCATION_REQ)
                        .contains(bodyTypeOfFirstRequest));
        try {
            final PKIMessage receivedMessage = PKIMessage.getInstance(rawReceivedMessage);
            if (LOGGER.isDebugEnabled()) {
                // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
                // enabled
                LOGGER.debug("CA: got:\n" + MessageDumper.dumpPkiMessage(receivedMessage));
            }
            lastReceivedMessages.addFirst(receivedMessage);
            while (lastReceivedMessages.size() > MAX_LAST_RECEIVED) {
                lastReceivedMessages.removeLast();
            }
            final PKIMessage ret;
            switch (receivedMessage.getBody().getType()) {
                case PKIBody.TYPE_INIT_REQ:
                case PKIBody.TYPE_CERT_REQ:
                case PKIBody.TYPE_KEY_UPDATE_REQ:
                    ret = handleCrmfCerticateRequest(receivedMessage);
                    break;
                case PKIBody.TYPE_P10_CERT_REQ:
                    ret = handleP10CerticateRequest(receivedMessage);
                    break;
                case PKIBody.TYPE_CERT_CONFIRM:
                    ret = handleCertConfirm(receivedMessage);
                    break;
                case PKIBody.TYPE_REVOCATION_REQ:
                    ret = handleRevocationRequest(receivedMessage);
                    break;
                default:
                    ret = generateError(
                            receivedMessage,
                            "unsuported message type "
                                    + receivedMessage.getBody().getType());
            }
            if (LOGGER.isDebugEnabled()) {
                // avoid unnecessary call of MessageDumper.dumpPkiMessage, if debug isn't
                // enabled
                LOGGER.debug("CA: respond:\n" + MessageDumper.dumpPkiMessage(ret));
            }
            return ret.getEncoded();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}
