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
package com.siemens.pki.cmpracomponent.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.util.function.Function;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.junit.Before;
import org.junit.Test;

/**
 * End-to-end test of the NESTED message nesting-depth limit in {@code RaDownstream}, following the
 * integration-test pattern of this project: a "real" RA instance (the full {@code CmpRaComponent})
 * is started up with the {@code CmpCaMock} used from source as its upstream, and a mock client
 * sends the request into the downstream interface.
 *
 * <p>
 * This complements the unit test {@code TestRaDownstreamNesting} by exercising the depth limit
 * through the whole message pipeline: downstream input validation, the NESTED endpoint's
 * unwrap/protection handling, forwarding to (and back from) the mock CA, and the reprotection of
 * the outgoing message.
 * </p>
 */
public class TestNestedMessageEndToEnd extends OnlineEnrollmentTestcaseBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestNestedMessageEndToEnd.class);

    @Before
    public void setUp() throws Exception {
        launchCmpCaAndRa(buildRaConfigurationWithNestedEndpoint());
    }

    /**
     * Control case: a plain (non-nested) certificate request is still processed end-to-end when a
     * nested endpoint is configured on the RA. Because the RA re-wraps outgoing responses in a
     * NESTED envelope whenever a nested endpoint is present, the client unwraps that single layer
     * before the standard enrollment assertion applies.
     */
    @Test
    public void testPlainCertificateRequest() throws Exception {
        executeCrmfCertificateRequest(
                PKIBody.TYPE_CERT_REQ, PKIBody.TYPE_CERT_REP,
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                nestedClient(0));
    }

    /**
     * Legitimate single-level NESTED wrapping (depth 1) must be unwrapped by the RA and the inner
     * certificate request processed end-to-end. Regression guard proving the nesting-depth limit
     * does not break the intended nested feature.
     */
    @Test
    public void testSingleLevelNestedCertificateRequestIsProcessed() throws Exception {
        executeCrmfCertificateRequest(
                PKIBody.TYPE_CERT_REQ, PKIBody.TYPE_CERT_REP,
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                nestedClient(1));
    }

    /**
     * Nesting at the boundary (2 NESTED wrappers = the maximum supported depth) must still be
     * unwrapped and the inner certificate request processed end-to-end.
     */
    @Test
    public void testBoundaryDepthNestedCertificateRequestIsProcessed() throws Exception {
        executeCrmfCertificateRequest(
                PKIBody.TYPE_CERT_REQ, PKIBody.TYPE_CERT_REP,
                ConfigurationFactory.getEeSignaturebasedProtectionProvider(),
                nestedClient(2));
    }

    /**
     * An over-deep self-recursive NESTED message (3 levels of wrapping) must be rejected by the RA
     * with a {@code badRequest} error body instead of exhausting the stack. The request never
     * reaches the mock CA, because the depth check is enforced before the message is forwarded.
     */
    @Test
    public void testOverlyDeepNestedMessageIsRejectedWithBadRequest() throws Exception {
        final ProtectionProvider eeProtectionProvider = ConfigurationFactory.getEeSignaturebasedProtectionProvider();
        final PKIMessage plain = executePlainCrRequest(eeProtectionProvider);
        final PKIMessage overdeep = nest(plain, 3);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("send (3x nested):\n" + MessageDumper.dumpPkiMessage(overdeep));
        }
        final PKIMessage response = getEeClient().apply(overdeep);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("got:\n" + MessageDumper.dumpPkiMessage(response));
        }

        assertEquals("message type", PKIBody.TYPE_ERROR, response.getBody().getType());
        final ErrorMsgContent errorContent = (ErrorMsgContent) response.getBody().getContent();
        final PKIStatusInfo statusInfo = errorContent.getPKIStatusInfo();
        assertNotNull("statusInfo", statusInfo);
        assertNotNull("failInfo must be present", statusInfo.getFailInfo());
        // the production code builds the failure info as new PKIFailureInfo(PKIFailureInfo.badRequest);
        // compare the ASN.1 encodings (independent of BouncyCastle's internal bit layout)
        final PKIFailureInfo expected = new PKIFailureInfo(PKIFailureInfo.badRequest);
        assertEquals(
                "failure reason must be badRequest",
                expected.toASN1Primitive(),
                statusInfo.getFailInfo().toASN1Primitive());
    }

    /**
     * Build the RA configuration for a single "real" RA whose downstream interface exposes an
     * active nested endpoint (i.e. the RA unwraps incoming NESTED messages). Everything else is
     * delegated to the proven signature-based single-RA configuration, so the inner certificate
     * request flow (validation, inventory, forwarding, reprotection) is identical to the standard
     * enrollment tests.
     */
    private static Configuration buildRaConfigurationWithNestedEndpoint() throws Exception {
        final Configuration base = TestNestedKur.buildSignaturebasedRaConfiguration();
        return new Configuration() {

            @Override
            public com.siemens.pki.cmpracomponent.configuration.CkgContext getCkgConfiguration(
                    final String certProfile, final int bodyType) {
                return base.getCkgConfiguration(certProfile, bodyType);
            }

            @Override
            public CmpMessageInterface getDownstreamConfiguration(final String certProfile, final int bodyType) {
                final CmpMessageInterface baseDownstream = base.getDownstreamConfiguration(certProfile, bodyType);
                return new CmpMessageInterface() {

                    @Override
                    public VerificationContext getInputVerification() {
                        return baseDownstream.getInputVerification();
                    }

                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return new NestedEndpointContext() {
                            @Override
                            public VerificationContext getInputVerification() {
                                // the mock client signs its nested wrappers with the EE credential,
                                // so validate incoming nested messages against the EE root
                                return new com.siemens.pki.cmpracomponent.test.framework
                                        .SignatureValidationCredentials("credentials/CMP_EE_Root.pem", null);
                            }

                            @Override
                            public CredentialContext getOutputCredentials() {
                                try {
                                    return new TrustChainAndPrivateKey(
                                            "credentials/CMP_CA_Keystore.p12", "Password".toCharArray());
                                } catch (final Exception e) {
                                    throw new RuntimeException(e);
                                }
                            }

                            @Override
                            public boolean isIncomingRecipientValid(final String recipient) {
                                LOGGER.debug("isIncomingRecipientValid called with recipient: {}", recipient);
                                return true;
                            }
                        };
                    }

                    @Override
                    public CredentialContext getOutputCredentials() {
                        return baseDownstream.getOutputCredentials();
                    }

                    @Override
                    public CmpMessageInterface.ReprotectMode getReprotectMode() {
                        return baseDownstream.getReprotectMode();
                    }

                    @Override
                    public boolean isEnforceReprotectMode() {
                        return baseDownstream.isEnforceReprotectMode();
                    }

                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return baseDownstream.getSuppressRedundantExtraCerts();
                    }

                    @Override
                    public boolean isCacheExtraCerts() {
                        return baseDownstream.isCacheExtraCerts();
                    }

                    @Override
                    public boolean isMessageTimeDeviationAllowed(final long deviation) {
                        return baseDownstream.isMessageTimeDeviationAllowed(deviation);
                    }
                };
            }

            @Override
            public int getDownstreamTimeout(final String certProfile, final int bodyType) {
                return base.getDownstreamTimeout(certProfile, bodyType);
            }

            @Override
            public VerificationContext getEnrollmentTrust(final String certProfile, final int bodyType) {
                return base.getEnrollmentTrust(certProfile, bodyType);
            }

            @Override
            public boolean getForceRaVerifyOnUpstream(final String certProfile, final int bodyType) {
                return base.getForceRaVerifyOnUpstream(certProfile, bodyType);
            }

            @Override
            public com.siemens.pki.cmpracomponent.configuration.InventoryInterface getInventory(
                    final String certProfile, final int bodyType) {
                return base.getInventory(certProfile, bodyType);
            }

            @Override
            public com.siemens.pki.cmpracomponent.configuration.PersistencyInterface getPersistency() {
                return base.getPersistency();
            }

            @Override
            public int getRetryAfterTimeInSeconds(final String certProfile, final int bodyType) {
                return base.getRetryAfterTimeInSeconds(certProfile, bodyType);
            }

            @Override
            public com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface
                    getSupportMessageHandler(final String certProfile, final String infoTypeOid) {
                return base.getSupportMessageHandler(certProfile, infoTypeOid);
            }

            @Override
            public CmpMessageInterface getUpstreamConfiguration(final String certProfile, final int bodyType) {
                return base.getUpstreamConfiguration(certProfile, bodyType);
            }

            @Override
            public boolean isRaVerifiedAcceptable(final String certProfile, final int bodyType) {
                return base.isRaVerifiedAcceptable(certProfile, bodyType);
            }
        };
    }

    /**
     * Build the plain, unprotected certificate request that {@code executeCrmfCertificateRequest}
     * would send, so the over-deep test can wrap exactly that message in NESTED envelopes.
     */
    private PKIMessage executePlainCrRequest(final ProtectionProvider protectionProvider) throws Exception {
        final java.security.KeyPair keyPair = ConfigurationFactory.getKeyGenerator().generateKeyPair();
        final org.bouncycastle.asn1.crmf.CertTemplateBuilder ctb = new org.bouncycastle.asn1.crmf.CertTemplateBuilder()
                .setPublicKey(
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()))
                .setSubject(new org.bouncycastle.asn1.x500.X500Name("CN=Subject"));
        final PKIBody crBody = PkiMessageGenerator.generateIrCrKurBody(
                PKIBody.TYPE_CERT_REQ, ctb.build(), null, keyPair.getPrivate());
        return PkiMessageGenerator.generateAndProtectMessage(
                new com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest(
                        "theCertProfileForOnlineEnrollment"),
                protectionProvider, crBody);
    }

    /**
     * Wrap {@code inner} in {@code nestingLevels} NESTED envelopes, each forwarding the header of
     * the wrapped message and signed with the EE credential (as a forwarding nested envelope does).
     */
    private static PKIMessage nest(final PKIMessage inner, final int nestingLevels) throws Exception {
        final ProtectionProvider protectionProvider =
                ConfigurationFactory.getEeSignaturebasedProtectionProvider();
        PKIMessage current = inner;
        for (int i = 0; i < nestingLevels; i++) {
            final PKIBody nestedBody = new PKIBody(
                    PKIBody.TYPE_NESTED, new PKIMessages(new PKIMessage[] {current}));
            current = PkiMessageGenerator.generateAndProtectMessage(
                    PkiMessageGenerator.buildForwardingHeaderProvider(current), protectionProvider, nestedBody);
        }
        return current;
    }

    /**
     * Build a client that NESTED-wraps every outgoing request in the given number of NESTED
     * envelopes (signed with the EE credential, as a forwarding nested envelope does) and unwraps
     * the single NESTED envelope from every incoming response. The RA re-wraps each outgoing
     * downstream response in exactly one NESTED envelope whenever a nested endpoint is configured,
     * regardless of the incoming nesting depth — and the over-deep error response is not wrapped
     * at all — so a single-layer unwrap is sufficient on the response side.
     */
    private Function<PKIMessage, PKIMessage> nestedClient(final int nestingLevels) {
        final Function<PKIMessage, PKIMessage> baseClient = getEeClient();
        return req -> {
            try {
                final PKIMessage outgoing = nestingLevels > 0 ? nest(req, nestingLevels) : req;
                return unwrapSingleNested(baseClient.apply(outgoing));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    /** Unwrap a single-layer NESTED response so the caller can work on the inner message. */
    private static PKIMessage unwrapSingleNested(final PKIMessage response) {
        if (response.getBody().getType() == PKIBody.TYPE_NESTED) {
            final PKIMessage[] embedded =
                    PKIMessages.getInstance(response.getBody().getContent()).toPKIMessageArray();
            if (embedded != null && embedded.length == 1) {
                return embedded[0];
            }
        }
        return response;
    }
}
