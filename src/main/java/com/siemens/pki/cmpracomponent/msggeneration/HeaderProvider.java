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
package com.siemens.pki.cmpracomponent.msggeneration;

import java.util.Date;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * data provider for all parameters required to build a CMP header.
 */
public interface HeaderProvider {

    /** get GeneralInfo (ImplicitConfirm, ConfirmWaitTime) to be used in CMP header
     * @return GeneralInfo
     */
    InfoTypeAndValue[] getGeneralInfo();

    /**
     * get MessageTime to be used in CMP header.
     * @return MessageTime
     */
    default ASN1GeneralizedTime getMessageTime() {
        return new DERGeneralizedTime(new Date());
    }

    /**
     * get CMP version to be used in CMP header.
     * @return CMP version
     */
    int getPvno();

    /**
     * get Recipient to be used in CMP header.
     * @return Recipient
     */
    GeneralName getRecipient();

    /**
     * get RecipNonce to be used in CMP header.
     * @return RecipNonce
     */
    ASN1OctetString getRecipNonce();

    /**
     * get Sender to be used in CMP header.
     * @return Sender
     */
    GeneralName getSender();

    /**
     * get SenderNonce to be used in CMP header.
     * @return SenderNonce
     */
    ASN1OctetString getSenderNonce();

    /**
     * get TransactionID to be used in CMP header.
     * @return TransactionID
     */
    ASN1OctetString getTransactionID();
}
