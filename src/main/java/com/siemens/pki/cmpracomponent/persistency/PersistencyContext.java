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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.siemens.pki.cmpracomponent.cmpextension.KemCiphertextInfo;
import com.siemens.pki.cmpracomponent.cmpextension.NewCMPObjectIdentifiers;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * holder for all persistent data
 */
public class PersistencyContext {

    public enum InterfaceContext {
        dowstream_rec,
        downstream_send,
        upstream_rec,
        upstream_send
    }

    static InitialKemContext fetchInitialKemContext(PKIMessage msg) {
        final PKIHeader header = msg.getHeader();
        if (header.getGeneralInfo() != null) {
            for (final InfoTypeAndValue itav : header.getGeneralInfo()) {
                if (NewCMPObjectIdentifiers.it_kemCiphertextInfo.equals(itav.getInfoType())) {
                    final KemCiphertextInfo kemCiphertextInfo = KemCiphertextInfo.getInstance(itav.getInfoValue());
                    if (kemCiphertextInfo != null) {
                        return new InitialKemContext(
                                header.getTransactionID(),
                                header.getSenderNonce(),
                                header.getRecipNonce(),
                                kemCiphertextInfo);
                    }
                }
            }
        }
        final InfoTypeAndValue[] itavs;
        if (msg.getBody().getType() == PKIBody.TYPE_GEN_MSG) {
            itavs = ((GenMsgContent) msg.getBody().getContent()).toInfoTypeAndValueArray();
        } else if (msg.getBody().getType() == PKIBody.TYPE_GEN_REP) {
            itavs = ((GenRepContent) msg.getBody().getContent()).toInfoTypeAndValueArray();
        } else {
            return null;
        }

        for (final InfoTypeAndValue itav : itavs) {
            if (NewCMPObjectIdentifiers.it_kemCiphertextInfo.equals(itav.getInfoType())) {
                final KemCiphertextInfo kemCiphertextInfo = KemCiphertextInfo.getInstance(itav.getInfoValue());
                if (kemCiphertextInfo != null) {
                    return new InitialKemContext(
                            header.getTransactionID(),
                            header.getSenderNonce(),
                            header.getRecipNonce(),
                            kemCiphertextInfo);
                }
            }
        }
        return null;
    }

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
    private ASN1OctetString lastSenderNonce;
    private byte[] digestToConfirm;
    private boolean implicitConfirmGranted;
    private byte[] requestedPublicKey;

    @JsonSerialize(contentAs = InitialKemContext.class)
    @JsonDeserialize(contentAs = InitialKemContext.class)
    private EnumMap<InterfaceContext, InitialKemContext> initialKemContexts;

    @JsonIgnore
    private List<CMPCertificate> issuingChain;

    @JsonIgnore
    private PersistencyContextManager contextManager;

    private int certificateRequestType;

    private boolean delayedDeliveryInProgress;

    /**
     * ctor used by jackson
     */
    public PersistencyContext() {}

    public PersistencyContext(final PersistencyContextManager contextManager, final byte[] transactionId) {
        this.transactionId = transactionId;
        this.contextManager = contextManager;
        lastTransactionState = LastTransactionState.INITIAL_STATE;
        this.certificateRequestType = -1;
        initialKemContexts = new EnumMap<>(InterfaceContext.class);
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
    public boolean getDelayedDeliveryInProgress() {
        return delayedDeliveryInProgress;
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

    public InitialKemContext getInitialKemContext(InterfaceContext interfaceContext) {
        return initialKemContexts.get(interfaceContext);
    }

    public PKIMessage getInitialRequest() {
        return initialRequest;
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

    public void markKemStart() {
        transactionStateTracker.markKemStart();
    }

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
     * mark transaction as delayed
     * @param delayedDeliveryInProgress true if transaction is delayed
     */
    public void setDelayedDeliveryInProgress(final boolean delayedDeliveryInProgress) {
        this.delayedDeliveryInProgress = delayedDeliveryInProgress;
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

    public void setInitialKemContext(
            InitialKemContext initialKemContext, PersistencyContext.InterfaceContext interfaceContext)
            throws CmpValidationException {
        if (initialKemContext == null) {
            return;
        }
        if (initialKemContexts.containsKey(interfaceContext)) {
            throw new CmpValidationException(
                    getCertProfile(), PKIFailureInfo.badMessageCheck, "unexpected reinitalization of KemOtherInfo");
        }
        initialKemContexts.put(interfaceContext, initialKemContext);
    }

    public void setInitialKemContext(PKIMessage msg, PersistencyContext.InterfaceContext interfaceContext)
            throws CmpValidationException {
        final InitialKemContext initialKemContext = fetchInitialKemContext(msg);
        if (initialKemContext != null) {
            setInitialKemContext(initialKemContext, interfaceContext);
        }
    }

    public void setInitialRequest(final PKIMessage initialRequest) {
        this.initialRequest = initialRequest;
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

    public void trackRequest(final PKIMessage msg) throws BaseCmpException, IOException {
        transactionStateTracker.trackMessage(msg);
    }

    public void trackResponse(final PKIMessage msg) throws BaseCmpException, IOException {
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
