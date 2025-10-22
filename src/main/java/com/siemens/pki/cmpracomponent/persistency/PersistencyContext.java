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
import org.bouncycastle.asn1.ASN1OctetString;
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
    private PKIMessage delayedInitialRequest;
    private PKIMessage pendingDelayedResponse;
    private LastTransactionState lastTransactionState;
    private ASN1OctetString lastSenderNonce;
    private byte[] digestToConfirm;
    private boolean implicitConfirmGranted;
    private byte[] requestedPublicKey;

    @JsonIgnore
    private List<CMPCertificate> issuingChain;

    @JsonIgnore
    private PersistencyContextManager contextManager;

    private int certificateRequestType;

    /**
     * ctor used by jackson
     */
    public PersistencyContext() {}

    /**
     * ctor
     * @param contextManager contextManager in charge
     * @param transactionId transactionId belonging to this PersistencyContext
     */
    PersistencyContext(final PersistencyContextManager contextManager, final byte[] transactionId) {
        this.transactionId = transactionId;
        this.contextManager = contextManager;
        lastTransactionState = LastTransactionState.INITIAL_STATE;
        this.certificateRequestType = -1;
    }

    /**
     * store or clear persisten state
     * @throws IOException en case of erro
     */
    public void flush() throws IOException {
        if (transactionStateTracker.isTransactionTerminated()) {
            contextManager.clearPersistencyContext(transactionId);
        } else {
            contextManager.flushPersistencyContext(this);
        }
    }

    /**
     * get sent extra certs, if compression is used
     * @return already sent extra certs
     */
    public Set<CMPCertificate> getAlreadySentExtraCerts() {
        if (alreadySentExtraCerts == null) {
            alreadySentExtraCerts = new HashSet<>();
        }
        return alreadySentExtraCerts;
    }

    /**
     * get certificate profile used in transaction
     * @return certificate profile or <code>null</code>
     */
    public String getCertProfile() {
        return certProfile;
    }

    /**
     * is the transaction delayed (polling)?
     * @return true if delayed
     */
    @JsonIgnore
    public boolean isDelayedDeliveryInProgress() {
        return delayedInitialRequest != null;
    }

    /**
     * get certificate digest to confirm
     * @return certificate digest or <code>null</code>
     */
    public byte[] getDigestToConfirm() {
        return digestToConfirm;
    }

    /**
     * get expiration time for related transaction
     * @return expiration time
     */
    public Date getExpirationTime() {
        return expirationTime;
    }

    /**
     * get first request of the transaction
     * @return first request
     */
    public PKIMessage getDelayedInitialRequest() {
        return delayedInitialRequest;
    }

    /**
     * get issueing chain
     * @return issueing chain
     */
    public List<CMPCertificate> getIssuingChain() {
        return issuingChain;
    }

    /**
     * get last used sender nonce
     * @return last used sender nonce
     */
    public ASN1OctetString getLastSenderNonce() {
        return lastSenderNonce;
    }

    /**
     * get last state of transaction
     * @return last state of transaction
     */
    public LastTransactionState getLastTransactionState() {
        return lastTransactionState;
    }

    /**
     * get central generated private key
     * @return  private key or <code>null</code>
     */
    public PrivateKey getNewGeneratedPrivateKey() {
        return newGeneratedPrivateKey;
    }

    /**
     * get pending upstream response in case of deöayed delivery
     * @return upstream response
     */
    public PKIMessage getPendingDelayedResponse() {
        return pendingDelayedResponse;
    }

    /**
     * get public key in CRMF template
     * @return public key
     */
    public byte[] getRequestedPublicKey() {
        return requestedPublicKey;
    }

    /**
     * get type of initial request
     * @return type of initial request
     */
    public int getRequestType() {
        return certificateRequestType;
    }

    /**
     * get TransactionId
     * @return TransactionId
     */
    public byte[] getTransactionId() {
        return transactionId;
    }

    /**
     * ImplicitConfirm used in transaction
     * @return true if ImplicitConfirm is used
     */
    public boolean isImplicitConfirmGranted() {
        return implicitConfirmGranted;
    }

    /**
     * mark the currently processed GENM as preparing for a remaining transaction
     */
    public void markAsPreparingGenm() {
        transactionStateTracker.markAsPreparingGenm();
    }

    /**
     * store  already sent extra certs in case of compression
     * @param alreadySentExtraCerts already sent extra certs
     */
    public void setAlreadySentExtraCerts(final Set<CMPCertificate> alreadySentExtraCerts) {
        this.alreadySentExtraCerts = alreadySentExtraCerts;
    }

    /**
     * set certificate profile
     * @param certProfile certificate profile or <code>null</code> if certificate profile should not change
     */
    public void setCertProfile(final String certProfile) {
        if (certProfile != null) {
            this.certProfile = certProfile;
        }
    }

    /**
     * set contextManager
     * @param contextManager the contextManager
     */
    public void setContextManager(final PersistencyContextManager contextManager) {
        this.contextManager = contextManager;
    }

    /**
     * set digestToConfirm
     * @param digestToConfirm the digestToConfirm
     */
    public void setDigestToConfirm(final byte[] digestToConfirm) {
        this.digestToConfirm = digestToConfirm;
    }

    /**
     * set transaction expiration time
     * @param expirationTime transaction expiration time
     */
    public void setExpirationTime(final Date expirationTime) {
        this.expirationTime = expirationTime;
    }

    /**
     * set implicitConfirmGranted
     * @param implicitConfirmGranted true if implict confirm used
     */
    public void setImplicitConfirmGranted(final boolean implicitConfirmGranted) {
        this.implicitConfirmGranted = implicitConfirmGranted;
    }

    /**
     * mark transaction as delayed delivery, store initial request
     * @param delayedInitialRequest the initial request triggering delayed delivery
     */
    public void setDelayedInitialRequest(final PKIMessage delayedInitialRequest) {
        if (this.delayedInitialRequest == null) {
            this.delayedInitialRequest = delayedInitialRequest;
        }
    }

    /**
     * set issuingChain
     * @param issuingChain the issuingChain
     */
    public void setIssuingChain(final List<CMPCertificate> issuingChain) {
        this.issuingChain = issuingChain;
    }

    /**
     * set lastSenderNonce
     * @param asn1OctetString the lastSenderNonce
     */
    public void setLastSenderNonce(final ASN1OctetString asn1OctetString) {
        this.lastSenderNonce = asn1OctetString;
    }

    /**
     * set lastTransactionState
     * @param lastTransactionState the lastTransactionState
     */
    public void setLastTransactionState(final LastTransactionState lastTransactionState) {
        this.lastTransactionState = lastTransactionState;
    }

    /**
     * set newGeneratedPrivateKey
     * @param newGeneratedPrivateKey the newGeneratedPrivateKey
     */
    public void setNewGeneratedPrivateKey(final PrivateKey newGeneratedPrivateKey) {
        this.newGeneratedPrivateKey = newGeneratedPrivateKey;
    }

    /**
     * set pending delayed response from upstream
     * @param delayedResponse the delayed response
     * @throws CmpProcessingException in case of error
     */
    public void setPendingDelayedResponse(final PKIMessage delayedResponse) throws CmpProcessingException {
        if (this.pendingDelayedResponse != null) {
            throw new CmpProcessingException(
                    "upstream persistency",
                    PKIFailureInfo.transactionIdInUse,
                    "duplicate response for same transactionID");
        }
        this.pendingDelayedResponse = delayedResponse;
    }

    /**
     * set requestedPublicKey
     * @param requestedPublicKey the requestedPublicKey
     */
    public void setRequestedPublicKey(final byte[] requestedPublicKey) {
        this.requestedPublicKey = requestedPublicKey;
    }

    /**
     * set certificateRequestType
     * @param certificateRequestType the certificateRequestType
     */
    public void setRequestType(final int certificateRequestType) {
        this.certificateRequestType = certificateRequestType;
    }

    /**
     * process an incoming message
     * @param msg message to process
     * @throws BaseCmpException in case of CMP relate error
     * @throws IOException in case of general error
     */
    public void trackMessage(final PKIMessage msg) throws BaseCmpException, IOException {
        transactionStateTracker.trackMessage(msg);
    }

    /**
     * update expirationTime
     * @param expirationTime new expirationTime
     */
    public void updateTransactionExpirationTime(final Date expirationTime) {
        // only downstream can expire
        this.expirationTime = expirationTime;
    }
}
