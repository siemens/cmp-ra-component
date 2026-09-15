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
package com.siemens.pki.cmpracomponent.msgprocessing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.siemens.pki.cmpracomponent.configuration.CkgContext;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface.ReprotectMode;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.PersistencyInterface;
import com.siemens.pki.cmpracomponent.configuration.SupportMessageHandlerInterface;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.persistency.DefaultPersistencyImplementation;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContextManager;
import com.siemens.pki.cmpracomponent.protection.NoProtection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Unit tests for the self-recursive NESTED message unwrapping in {@link RaDownstream}.
 *
 * <p>
 * The downstream handler used to unwrap incoming NESTED messages recursively
 * ({@code handleInputMessage} -> {@code handleNestedRequest} -> {@code handleInputMessage} ...)
 * with no bound on the nesting depth, so a message wrapped N times in NESTED messages caused N
 * recursive validator invocations and, for large N, a {@link StackOverflowError}. These tests
 * verify that the (configurable) depth limit is enforced (an over-deep NESTED message is
 * rejected with a {@code badRequest} error body) while legitimate nesting is still processed,
 * for the default limit and for custom limits via
 * {@code NestedEndpointContext#getMaximumNestingDepth()}.
 * </p>
 */
@RunWith(Parameterized.class)
public class TestRaDownstreamNesting {

    private static final byte[] TXN_ID = "0123456789abcdef".getBytes();

    /** nesting-depth limit used for the "default" parameter (the interface default value). */
    private static final int LIMIT_DEFAULT = NestedEndpointContext.DEFAULT_MAX_NESTING_DEPTH;

    /** nesting-levels / limit pairs: (plain, single-level, boundary, over-deep) for each limit. */
    private static final int[][] TEST_DATA = {
        //
        {0, 1, LIMIT_DEFAULT, LIMIT_DEFAULT + 1}, // default limit
        //
        {0, 1, 1, 2}, // custom limit of 1
        //
        {0, 1, 3, 4}, // custom limit of 3
        //
    };

    @Parameters(name = "{index}: maxNestingDepth=>{1}")
    public static Collection<Object[]> testData() {
        final Collection<Object[]> params = new ArrayList<>(TEST_DATA.length);
        for (final int[] data : TEST_DATA) {
            params.add(new Object[] {data[0], data[1], data[2], data[3]});
        }
        return params;
    }

    private final int plainDepth;

    private final int singleLevelDepth;

    private final int boundaryDepth;

    private final int overDeepDepth;

    public TestRaDownstreamNesting(
            final int plainDepth, final int singleLevelDepth, final int boundaryDepth, final int overDeepDepth) {
        this.plainDepth = plainDepth;
        this.singleLevelDepth = singleLevelDepth;
        this.boundaryDepth = boundaryDepth;
        this.overDeepDepth = overDeepDepth;
    }

    private RaDownstream raDownstream;

    @Before
    public void setUp() {
        raDownstream = buildRaDownstream(boundaryDepth);
    }

    /**
     * An over-deep self-recursive NESTED message (nesting one level above the configured limit)
     * must be rejected with a {@code badRequest} error body instead of exhausting the stack.
     */
    @Test
    public void testOverlyDeepNestedMessageIsRejectedWithBadRequest() {
        final PKIMessage nestedMessage = nest(genmRequest(), overDeepDepth);
        final PKIMessage response = unwrapNested(raDownstream.handleInputMessage(nestedMessage));

        assertEquals("message type", PKIBody.TYPE_ERROR, response.getBody().getType());
        final ErrorMsgContent errorContent =
                (ErrorMsgContent) response.getBody().getContent();
        final PKIStatusInfo statusInfo = errorContent.getPKIStatusInfo();
        assertNotNull("statusInfo", statusInfo);
        assertNotNull("failInfo must be present", statusInfo.getFailInfo());
        // compare the ASN.1 encodings (independent of BC's internal bit layout)
        final PKIFailureInfo expected = new PKIFailureInfo(PKIFailureInfo.badRequest);
        assertEquals(
                "failure reason must be badRequest",
                expected.toASN1Primitive(),
                statusInfo.getFailInfo().toASN1Primitive());
    }

    /**
     * Nesting at the boundary (depth equal to the configured limit, still allowed) must be
     * processed normally.
     */
    @Test
    public void testBoundaryDepthNestedMessageIsProcessed() {
        final PKIMessage nestedMessage = nest(genmRequest(), boundaryDepth);
        final PKIMessage response = unwrapNested(raDownstream.handleInputMessage(nestedMessage));

        assertEquals("message type", PKIBody.TYPE_GEN_REP, response.getBody().getType());
    }

    /**
     * A legitimate single-level NESTED message must still be unwrapped and processed normally
     * (the regression guard proving the limit does not break the intended feature).
     */
    @Test
    public void testSingleLevelNestedMessageIsStillProcessed() {
        final PKIMessage nestedMessage = nest(genmRequest(), singleLevelDepth);
        final PKIMessage response = unwrapNested(raDownstream.handleInputMessage(nestedMessage));

        assertEquals("message type", PKIBody.TYPE_GEN_REP, response.getBody().getType());
    }

    /**
     * A plain (non-nested) request must still be processed normally.
     */
    @Test
    public void testPlainRequestStillProcessed() {
        final PKIMessage nestedMessage = nest(genmRequest(), plainDepth);
        final PKIMessage response = unwrapNested(raDownstream.handleInputMessage(nestedMessage));
        assertEquals("message type", PKIBody.TYPE_GEN_REP, response.getBody().getType());
    }

    // ----- test fixtures ---------------------------------------------------

    /**
     * Build a {@link RaDownstream} whose nested endpoint is active (unprotected, always unwraps)
     * and whose upstream is mocked to answer a GENM request with a GENRE, so a nested (or plain)
     * GENM can be processed end-to-end without any crypto.
     */
    private static RaDownstream buildRaDownstream(final int maxNestingDepth) {
        final Configuration config = new Configuration() {
            @Override
            public CkgContext getCkgConfiguration(final String certProfile, final int bodyType) {
                return null;
            }

            @Override
            public CmpMessageInterface getDownstreamConfiguration(final String certProfile, final int bodyType) {
                return new CmpMessageInterface() {
                    @Override
                    public VerificationContext getInputVerification() {
                        // no protection validation -> unprotected messages are accepted
                        return null;
                    }

                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return new NestedEndpointContext() {
                            @Override
                            public int getMaximumNestingDepth() {
                                return maxNestingDepth;
                            }

                            @Override
                            public VerificationContext getInputVerification() {
                                // no protection validation for the nested endpoint
                                return null;
                            }

                            @Override
                            public CredentialContext getOutputCredentials() {
                                // no protection on outgoing nested responses
                                return null;
                            }

                            @Override
                            public boolean isIncomingRecipientValid(final String recipient) {
                                // always unwrap incoming nested messages
                                return true;
                            }
                        };
                    }

                    @Override
                    public CredentialContext getOutputCredentials() {
                        return null;
                    }

                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.keep;
                    }

                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isCacheExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isMessageTimeDeviationAllowed(final long deviation) {
                        return true;
                    }
                };
            }

            @Override
            public int getDownstreamTimeout(final String certProfile, final int bodyType) {
                return 0;
            }

            @Override
            public VerificationContext getEnrollmentTrust(final String certProfile, final int bodyType) {
                return null;
            }

            @Override
            public boolean getForceRaVerifyOnUpstream(final String certProfile, final int bodyType) {
                return false;
            }

            @Override
            public InventoryInterface getInventory(final String certProfile, final int bodyType) {
                return null;
            }

            @Override
            public int getRetryAfterTimeInSeconds(final String certProfile, final int bodyType) {
                return 1;
            }

            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    final String certProfile, final String infoTypeOid) {
                return null;
            }

            @Override
            public CmpMessageInterface getUpstreamConfiguration(final String certProfile, final int bodyType) {
                return new CmpMessageInterface() {
                    @Override
                    public VerificationContext getInputVerification() {
                        return null;
                    }

                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return null;
                    }

                    @Override
                    public CredentialContext getOutputCredentials() {
                        return null;
                    }

                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.keep;
                    }

                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isCacheExtraCerts() {
                        return false;
                    }

                    @Override
                    public boolean isMessageTimeDeviationAllowed(final long deviation) {
                        return true;
                    }
                };
            }

            @Override
            public boolean isRaVerifiedAcceptable(final String certProfile, final int bodyType) {
                return true;
            }
        };
        final Collection<Integer> supported = Arrays.asList(PKIBody.TYPE_GEN_MSG, PKIBody.TYPE_GEN_REP);
        // upstream mock: answer a GENM with a GENRE (unprotected)
        final RaUpstream upstream = (in, persistencyContext) -> {
            try {
                return PkiMessageGenerator.generateAndProtectMessage(
                        PkiMessageGenerator.buildRespondingHeaderProvider(in),
                        new NoProtection(),
                        new PKIBody(
                                PKIBody.TYPE_GEN_REP,
                                new GenRepContent(new InfoTypeAndValue(CMPObjectIdentifiers.id_it_caCerts))));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        final PersistencyInterface persistency = new DefaultPersistencyImplementation(1000L);
        final PersistencyContextManager manager = new PersistencyContextManager(persistency);
        return new RaDownstream(manager, config, upstream, supported);
    }

    // ----- message builders ------------------------------------------------

    /** a plain, unprotected GENM request with a valid header (no protection required) */
    private static PKIMessage genmRequest() {
        return new PKIMessage(
                buildValidHeader(),
                new PKIBody(
                        PKIBody.TYPE_GEN_MSG,
                        new GenMsgContent(new InfoTypeAndValue(CMPObjectIdentifiers.id_it_caCerts))));
    }

    /**
     * Wrap {@code inner} in {@code nestingLevels} layers of NESTED messages. Each wrapper forwards
     * the header of the wrapped message (as a forwarding NESTED envelope does).
     */
    private static PKIMessage nest(final PKIMessage inner, final int nestingLevels) {
        PKIMessage current = inner;
        for (int i = 0; i < nestingLevels; i++) {
            current = new PKIMessage(
                    current.getHeader(), new PKIBody(PKIBody.TYPE_NESTED, new PKIMessages(new PKIMessage[] {current})));
        }
        return current;
    }

    /**
     * Build a header that passes {@code MessageHeaderValidator}: pvno 2000, real DN sender and
     * recipient, fresh 16-byte transactionID and senderNonce, current messageTime.
     */
    private static PKIHeader buildValidHeader() {
        final PKIHeaderBuilder builder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=EE-Mock")),
                new GeneralName(new X500Name("CN=RA-Mock")));
        builder.setTransactionID(TXN_ID);
        builder.setSenderNonce(TXN_ID);
        builder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        return builder.build();
    }

    /**
     * Unwrap a single-layer NESTED response (the downstream re-wraps outgoing responses in a
     * NESTED message when the nested endpoint is configured) so tests can assert on the payload.
     */
    private static PKIMessage unwrapNested(final PKIMessage response) {
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
