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
package com.siemens.pki.cmpracomponent.persistency;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * holder for all persistent data
 */
public class PersistencyContext {

    @JsonIgnore
    private final TransactionStateTracker transactionStateTracker = new TransactionStateTracker(this);

    private Date expirationTime;
    private byte[] transactionId;
    private String certProfile;
    private PrivateKey newGeneratedPrivateKey;
    private Set<CMPCertificate> alreadySentExtraCerts;
    private PKIMessage initialRequest;
    private PKIMessage pendingDelayedResponse;
    private LastTransactionState lastTransactionState;
    private byte[] lastSenderNonce;
    private byte[] digestToConfirm;
    private boolean implicitConfirmGranted;
    private byte[] requestedPublicKey;

    @JsonIgnore
    private List<CMPCertificate> issuingChain;

    @JsonIgnore
    private PersistencyContextManager contextManager;

    private int certificateRequestType;
    private boolean delayedDeliveryInProgress;

    public PersistencyContext() {}

    PersistencyContext(final PersistencyContextManager contextManager, final byte[] transactionId) {
        this.transactionId = transactionId;
        this.contextManager = contextManager;
        lastTransactionState = LastTransactionState.INITIAL_STATE;
        this.certificateRequestType = -1;
    }

    public void flush() throws IOException {
        if (transactionStateTracker.isTransactionTerminated()) {
            contextManager.clearPersistencyContext(transactionId);
        } else {
            contextManager.flushPersistencyContext(this);
        }
    }

    public Set<CMPCertificate> getAlreadySentExtraCerts() {
        if (alreadySentExtraCerts == null) {
            alreadySentExtraCerts = new HashSet<>();
        }
        return alreadySentExtraCerts;
    }

    public String getCertProfile() {
        return certProfile;
    }

    public boolean getDelayedDeliveryInProgress() {
        return delayedDeliveryInProgress;
    }

    public byte[] getDigestToConfirm() {
        return digestToConfirm;
    }

    public Date getExpirationTime() {
        return expirationTime;
    }

    public PKIMessage getInitialRequest() {
        return initialRequest;
    }

    public List<CMPCertificate> getIssuingChain() {
        return issuingChain;
    }

    public byte[] getLastSenderNonce() {
        return lastSenderNonce;
    }

    public LastTransactionState getLastTransactionState() {
        return lastTransactionState;
    }

    public PrivateKey getNewGeneratedPrivateKey() {
        return newGeneratedPrivateKey;
    }

    public PKIMessage getPendingDelayedResponse() {
        return pendingDelayedResponse;
    }

    public byte[] getRequestedPublicKey() {
        return requestedPublicKey;
    }

    public int getRequestType() {
        return certificateRequestType;
    }

    public byte[] getTransactionId() {
        return transactionId;
    }

    public boolean isImplicitConfirmGranted() {
        return implicitConfirmGranted;
    }

    public void setAlreadySentExtraCerts(final Set<CMPCertificate> alreadySentExtraCerts) {
        this.alreadySentExtraCerts = alreadySentExtraCerts;
    }

    public void setCertProfile(final String certProfile) {
        if (certProfile != null) {
            this.certProfile = certProfile;
        }
    }

    public void setContextManager(final PersistencyContextManager contextManager) {
        this.contextManager = contextManager;
    }

    public void setDelayedDeliveryInProgress(final boolean delayedDeliveryInProgress) {
        this.delayedDeliveryInProgress = delayedDeliveryInProgress;
    }

    public void setDigestToConfirm(final byte[] digestToConfirm) {
        this.digestToConfirm = digestToConfirm;
    }

    public void setExpirationTime(final Date expirationTime) {
        this.expirationTime = expirationTime;
    }

    public void setImplicitConfirmGranted(final boolean implicitConfirmGranted) {
        this.implicitConfirmGranted = implicitConfirmGranted;
    }

    public void setInitialRequest(final PKIMessage initialRequest) {
        this.initialRequest = initialRequest;
    }

    public void setIssuingChain(final List<CMPCertificate> issuingChain) {
        this.issuingChain = issuingChain;
    }

    public void setLastSenderNonce(final byte[] lastSenderNonce) {
        this.lastSenderNonce = lastSenderNonce;
    }

    public void setLastTransactionState(final LastTransactionState lastTransactionState) {
        this.lastTransactionState = lastTransactionState;
    }

    public void setNewGeneratedPrivateKey(final PrivateKey newGeneratedPrivateKey) {
        this.newGeneratedPrivateKey = newGeneratedPrivateKey;
    }

    public void setPendingDelayedResponse(final PKIMessage delayedResponse) throws CmpProcessingException {
        if (this.pendingDelayedResponse != null) {
            throw new CmpProcessingException(
                    "upstream persistency",
                    PKIFailureInfo.transactionIdInUse,
                    "duplicate response for same transactionID");
        }
        this.pendingDelayedResponse = delayedResponse;
    }

    public void setRequestedPublicKey(final byte[] requestedPublicKey) {
        this.requestedPublicKey = requestedPublicKey;
    }

    public void setRequestType(final int certificateRequestType) {
        this.certificateRequestType = certificateRequestType;
    }

    public void trackMessage(final PKIMessage msg) throws BaseCmpException, IOException {
        transactionStateTracker.trackMessage(msg);
    }

    public void updateTransactionExpirationTime(final Date downstreamExpirationTime) {
        // only downstream can expire
        this.expirationTime = downstreamExpirationTime;
    }
}
