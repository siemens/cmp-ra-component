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

import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.msggeneration.HeaderProvider;
import java.util.Date;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 *
 */
public class HeaderProviderForTest implements HeaderProvider {
    final ASN1OctetString transactionId;
    final ASN1OctetString senderNonce = new DEROctetString(CertUtility.generateRandomBytes(16));

    private final ASN1GeneralizedTime messageTime = new DERGeneralizedTime(new Date());
    private final ASN1OctetString recipientNonce;
    private final int pvno;
    private String certProfile = null;

    public HeaderProviderForTest(final int pvno, final String certProfile) {
        this.recipientNonce = null;
        this.certProfile = certProfile;
        this.transactionId = new DEROctetString(CertUtility.generateRandomBytes(16));
        this.pvno = pvno;
    }

    public HeaderProviderForTest(final PKIHeader lastHeader) {
        this.transactionId = lastHeader.getTransactionID();
        this.recipientNonce = lastHeader.getSenderNonce();
        this.pvno = lastHeader.getPvno().intValueExact();
    }

    public HeaderProviderForTest(final String certProfile) {
        this(PKIHeader.CMP_2000, certProfile);
    }

    @Override
    public InfoTypeAndValue[] getGeneralInfo() {
        return ifNotNull(certProfile, x -> new InfoTypeAndValue[] {
            new InfoTypeAndValue(CMPObjectIdentifiers.id_it_certProfile, new DERSequence(new DERUTF8String(x)))
        });
    }

    @Override
    public ASN1GeneralizedTime getMessageTime() {
        return messageTime;
    }

    @Override
    public int getPvno() {
        return pvno;
    }

    @Override
    public GeneralName getRecipient() {
        return new GeneralName(new X500Name("CN=CA-Mock"));
    }

    @Override
    public ASN1OctetString getRecipNonce() {
        return recipientNonce;
    }

    @Override
    public GeneralName getSender() {
        return new GeneralName(new X500Name("CN=EE-Mock"));
    }

    @Override
    public ASN1OctetString getSenderNonce() {
        return senderNonce;
    }

    @Override
    public ASN1OctetString getTransactionID() {
        return transactionId;
    }
}
