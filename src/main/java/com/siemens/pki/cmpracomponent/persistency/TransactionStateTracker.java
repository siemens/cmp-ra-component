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
package com.siemens.pki.cmpracomponent.persistency;

import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** handler for one transaction identified by a transactionId */
class TransactionStateTracker {

    private static final DefaultDigestAlgorithmIdentifierFinder digestFinder =
            new DefaultDigestAlgorithmIdentifierFinder();

    private static final Logger LOGGER = LoggerFactory.getLogger(TransactionStateTracker.class);

    private static final String INTERFACE_NAME = "CMP RA Component";

    private static DigestCalculatorProvider digestProvider;

    static {
        try {
            digestProvider = new JcaDigestCalculatorProviderBuilder().build();
        } catch (final OperatorCreationException e) {
            LOGGER.error("JcaDigestCalculatorProviderBuilder", e);
        }
    }

    private final PersistencyContext persistencyContext;

    TransactionStateTracker(final PersistencyContext persistencyContext) {
        this.persistencyContext = persistencyContext;
    }

    private boolean grantsImplicitConfirm(final PKIMessage msg) {
        final InfoTypeAndValue[] generalInfo = msg.getHeader().getGeneralInfo();
        if (generalInfo == null) {
            return false;
        }
        for (final InfoTypeAndValue aktGenInfo : generalInfo) {
            if (aktGenInfo.getInfoType().equals(CMPObjectIdentifiers.it_implicitConfirm)) {
                return true;
            }
        }
        return false;
    }

    private void handleCertResponse(final PKIMessage msg) throws CmpValidationException, CmpProcessingException {
        persistencyContext.setImplicitConfirmGranted(
                persistencyContext.isImplicitConfirmGranted() && grantsImplicitConfirm(msg));
        try {
            final Certificate enrolledCertificate = ((CertRepMessage)
                            msg.getBody().getContent())
                    .getResponse()[0]
                    .getCertifiedKeyPair()
                    .getCertOrEncCert()
                    .getCertificate()
                    .getX509v3PKCert();
            final DigestCalculator dc =
                    digestProvider.get(digestFinder.find(enrolledCertificate.getSignatureAlgorithm()));
            dc.getOutputStream().write(enrolledCertificate.getEncoded(ASN1Encoding.DER));
            persistencyContext.setDigestToConfirm(dc.getDigest());
            final SubjectPublicKeyInfo enrolledPublicKey = enrolledCertificate.getSubjectPublicKeyInfo();
            if (!Arrays.equals(
                    persistencyContext.getRequestedPublicKey(), enrolledPublicKey.getEncoded(ASN1Encoding.DER))) {
                throw new CmpValidationException(
                        INTERFACE_NAME, PKIFailureInfo.badMessageCheck, "wrong public key in cert response");
            }
            persistencyContext.setLastTransactionState(LastTransactionState.CERTIFICATE_RECEIVED);
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception e) {
            persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
            throw new CmpProcessingException(
                    INTERFACE_NAME,
                    PKIFailureInfo.badMessageCheck,
                    "could not calculate certificate hash:" + e.getLocalizedMessage() + " for "
                            + MessageDumper.msgAsShortString(msg));
        }
    }

    private boolean isCertConfirm(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_CERT_CONFIRM;
    }

    private boolean isCertRequest(final PKIMessage msg) {
        switch (msg.getBody().getType()) {
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
            case PKIBody.TYPE_P10_CERT_REQ:
                return true;
            default:
                return false;
        }
    }

    private boolean isCertResponse(final PKIMessage msg) {
        switch (msg.getBody().getType()) {
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP:
                return true;
            default:
                return false;
        }
    }

    private boolean isCertResponseWithWaitingIndication(final PKIMessage msg) {
        try {
            return ((CertRepMessage) msg.getBody().getContent())
                            .getResponse()[0]
                            .getStatus()
                            .getStatus()
                            .intValue()
                    == PKIStatus.WAITING;
        } catch (final Exception ex) {
            return false;
        }
    }

    private boolean isConfirmConfirm(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_CONFIRM;
    }

    private boolean isError(final PKIMessage msg) {
        final PKIBody body = msg.getBody();
        switch (body.getType()) {
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP: {
                final CertResponse[] responses = ((CertRepMessage) body.getContent()).getResponse();
                if (responses != null && responses.length == 1 && responses[0].getStatus() != null) {
                    switch (responses[0].getStatus().getStatus().intValue()) {
                        case PKIStatus.GRANTED:
                        case PKIStatus.GRANTED_WITH_MODS:
                        case PKIStatus.WAITING:
                            return false;
                    }
                    return true;
                }
                return false;
            }
            case PKIBody.TYPE_CERT_CONFIRM: {
                final CertStatus[] responses = ((CertConfirmContent) body.getContent()).toCertStatusArray();
                if (responses != null && responses.length == 1 && responses[0].getStatusInfo() != null) {
                    switch (responses[0].getStatusInfo().getStatus().intValue()) {
                        case PKIStatus.GRANTED:
                        case PKIStatus.GRANTED_WITH_MODS:
                            return false;
                    }
                    return true;
                }
                return false;
            }
            case PKIBody.TYPE_ERROR:
                final ErrorMsgContent errorContent = (ErrorMsgContent) body.getContent();
                return errorContent.getPKIStatusInfo().getStatus().intValue() != PKIStatus.WAITING;
        }
        return false;
    }

    private boolean isGenMessage(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_GEN_MSG;
    }

    private boolean isGenRep(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_GEN_REP;
    }

    private boolean isP10CertRequest(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_P10_CERT_REQ;
    }

    private boolean isPollRequest(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_POLL_REQ;
    }

    private boolean isPollResponse(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_POLL_REP;
    }

    private boolean isResponse(final PKIMessage msg) {
        switch (msg.getBody().getType()) {
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP:
            case PKIBody.TYPE_ERROR:
            case PKIBody.TYPE_GEN_REP:
            case PKIBody.TYPE_POLL_REP:
                return true;
        }
        return false;
    }

    private boolean isRevocationRequest(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_REVOCATION_REQ;
    }

    private boolean isRevocationResponse(final PKIMessage msg) {
        return msg.getBody().getType() == PKIBody.TYPE_REVOCATION_REP;
    }

    private boolean isSecondRequest(final PKIMessage msg) {
        switch (msg.getBody().getType()) {
            case PKIBody.TYPE_POLL_REQ:
            case PKIBody.TYPE_CERT_CONFIRM:
                return true;
            default:
                return false;
        }
    }

    boolean isTransactionTerminated() {
        switch (persistencyContext.getLastTransactionState()) {
            case CONFIRM_CONFIRMED:
            case GENREP_RETURNED:
            case IN_ERROR_STATE:
            case REVOCATION_CONFIRMED:
                return true;
            case CERTIFICATE_RECEIVED:
                return persistencyContext.isImplicitConfirmGranted();
            default:
                return false;
        }
    }

    private boolean isWaitingIndication(final PKIMessage msg) {
        final PKIBody body = msg.getBody();
        switch (body.getType()) {
            case PKIBody.TYPE_CERT_REP:
            case PKIBody.TYPE_INIT_REP:
            case PKIBody.TYPE_KEY_UPDATE_REP: {
                final CertResponse[] responses = ((CertRepMessage) body.getContent()).getResponse();
                if (responses != null && responses.length == 1 && responses[0].getStatus() != null) {
                    return responses[0].getStatus().getStatus().intValue() == PKIStatus.WAITING;
                }
                return false;
            }
            case PKIBody.TYPE_ERROR: {
                final ErrorMsgContent errorContent = (ErrorMsgContent) body.getContent();
                return errorContent.getPKIStatusInfo().getStatus().intValue() == PKIStatus.WAITING;
            }
            default:
                return false;
        }
    }

    /**
     * the main state machine
     *
     * @param message message to process
     * @throws BaseCmpException in case of failed CMP processing
     * @throws IOException in case of broken ASN.1
     */
    public void trackMessage(final PKIMessage message) throws BaseCmpException, IOException {
        if (isResponse(message)) {
            persistencyContext.setLastSenderNonce(message.getHeader().getSenderNonce());
        }
        if (isError(message)) {
            persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
            return;
        }
        if (isSecondRequest(message)) {
            if (persistencyContext.getLastTransactionState() == LastTransactionState.INITIAL_STATE) {
                throw new CmpValidationException(
                        INTERFACE_NAME,
                        PKIFailureInfo.transactionIdInUse,
                        "unexpected transcation ID for " + MessageDumper.msgAsShortString(message));
            }
            if (!Objects.equals(
                    persistencyContext.getLastSenderNonce(), message.getHeader().getRecipNonce())) {
                throw new CmpValidationException(
                        INTERFACE_NAME,
                        PKIFailureInfo.badRecipientNonce,
                        "sender/recipient nonce mismatch for " + MessageDumper.msgAsShortString(message));
            }
        }
        switch (persistencyContext.getLastTransactionState()) {
            case IN_ERROR_STATE:
                if (!isConfirmConfirm(message)) {
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.transactionIdInUse,
                            "got " + MessageDumper.msgTypeAsString(message)
                                    + ", but transaction already in error state");
                }
                return;
            case INITIAL_STATE:
                if (isGenMessage(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.GENM_RECEIVED);
                    return;
                }
                if (isRevocationRequest(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.REVOCATION_SENT);
                    return;
                }
                if (!isCertRequest(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction does not start with a request for " + MessageDumper.msgAsShortString(message));
                }
                if (isP10CertRequest(message)) {
                    persistencyContext.setRequestedPublicKey(
                            ((CertificationRequest) message.getBody().getContent())
                                    .getCertificationRequestInfo()
                                    .getSubjectPublicKeyInfo()
                                    .getEncoded());
                } else {
                    persistencyContext.setRequestedPublicKey(
                            ((CertReqMessages) message.getBody().getContent())
                                    .toCertReqMsgArray()[0]
                                    .getCertReq()
                                    .getCertTemplate()
                                    .getPublicKey()
                                    .getEncoded());
                }
                persistencyContext.setImplicitConfirmGranted(
                        persistencyContext.isImplicitConfirmGranted() && grantsImplicitConfirm(message));
                persistencyContext.setLastTransactionState(LastTransactionState.CERTIFICATE_REQUEST_SENT);
                return;
            case CERTIFICATE_REQUEST_SENT:
                if (isCertRequest(message)) {
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.transactionIdInUse,
                            "second request seen in transaction for " + MessageDumper.msgAsShortString(message));
                }
                if (!isCertResponse(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.badMessageCheck,
                            "request was not answered by cert response for " + MessageDumper.msgAsShortString(message));
                }
                if (isCertResponseWithWaitingIndication(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.CERTIFICATE_POLLING);
                    return;
                }
                handleCertResponse(message);
                return;
            case CERTIFICATE_POLLING:
                if (isPollRequest(message) || isPollResponse(message)) {
                    return;
                }
                if (!isCertResponse(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.badMessageCheck,
                            "request was not answered by cert response for " + MessageDumper.msgAsShortString(message));
                }
                handleCertResponse(message);
                return;
            case CERTIFICATE_RECEIVED:
                if (!isCertConfirm(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.badMessageCheck,
                            "response was not answered with confirmation for "
                                    + MessageDumper.msgAsShortString(message));
                }
                if (!Arrays.equals(
                        persistencyContext.getDigestToConfirm(),
                        ((CertConfirmContent) message.getBody().getContent())
                                .toCertStatusArray()[0]
                                .getCertHash()
                                .getOctets())) {
                    persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.badCertId,
                            "wrong hash in cert confirmation for " + MessageDumper.msgAsShortString(message));
                }
                persistencyContext.setLastTransactionState(LastTransactionState.CERTIFICATE_CONFIRMEND);
                return;
            case CERTIFICATE_CONFIRMEND:
                if (!isConfirmConfirm(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.IN_ERROR_STATE);
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.badMessageCheck,
                            "cert confirm was not answered with pki confirm for "
                                    + MessageDumper.msgAsShortString(message));
                }
                persistencyContext.setLastTransactionState(LastTransactionState.CONFIRM_CONFIRMED);
                return;
            case REVOCATION_SENT:
                if (isWaitingIndication(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.REVOCATION_POLLING);
                    return;
                }
                if (!isRevocationResponse(message)) {
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction in wrong state for " + MessageDumper.msgAsShortString(message));
                }
                persistencyContext.setLastTransactionState(LastTransactionState.REVOCATION_CONFIRMED);
                return;
            case REVOCATION_POLLING:
                if (isPollRequest(message) || isPollResponse(message)) {
                    return;
                }
                if (!isRevocationResponse(message)) {
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction in wrong state for " + MessageDumper.msgAsShortString(message));
                }
                persistencyContext.setLastTransactionState(LastTransactionState.REVOCATION_CONFIRMED);
                return;
            case GENM_RECEIVED:
                if (isWaitingIndication(message)) {
                    persistencyContext.setLastTransactionState(LastTransactionState.GEN_POLLING);
                    return;
                }
                if (!isGenRep(message)) {
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction in wrong state for " + MessageDumper.msgAsShortString(message));
                }
                persistencyContext.setLastTransactionState(LastTransactionState.GENREP_RETURNED);
                return;
            case GEN_POLLING:
                if (isPollRequest(message) || isPollResponse(message)) {
                    return;
                }
                if (!isGenRep(message)) {
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.transactionIdInUse,
                            "transaction in wrong state for " + MessageDumper.msgAsShortString(message));
                }
                persistencyContext.setLastTransactionState(LastTransactionState.GENREP_RETURNED);
                return;
            default:
                throw new CmpValidationException(
                        INTERFACE_NAME,
                        PKIFailureInfo.transactionIdInUse,
                        "transaction in wrong state (" + persistencyContext.getLastTransactionState() + ") for "
                                + MessageDumper.msgAsShortString(message));
        }
    }
}
