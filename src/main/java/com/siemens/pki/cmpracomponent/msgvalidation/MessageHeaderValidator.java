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
package com.siemens.pki.cmpracomponent.msgvalidation;

import java.util.Objects;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class MessageHeaderValidator implements ValidatorIF<String> {

    private final String interfaceName;

    public MessageHeaderValidator(final String interfaceName) {
        this.interfaceName = interfaceName;
    }

    /**
     * Validates the {@link PKIHeader header} of the given {@link PKIMessage
     * message}.<br>
     * <strong>Note:</strong><br>
     * See RFC4210 Section 5.1.1. PKI Message Header for further details.
     *
     * @param message
     *            the message to validate
     * @return certProfile or <code>null</code> if certProfile was not found in
     *         header
     * @throws BaseCmpException
     *             in case of failed validation
     */
    @Override
    public String validate(final PKIMessage message) throws BaseCmpException {
        assertValueNotNull(message, PKIFailureInfo.badDataFormat, "PKIMessage");
        final PKIHeader header = message.getHeader();
        assertValueNotNull(header, PKIFailureInfo.badDataFormat, "header");
        final ASN1Integer pvno = header.getPvno();
        assertValueNotNull(pvno, PKIFailureInfo.unsupportedVersion,
                "pvno is null");
        final long versionNumber = pvno.longValueExact();
        if (versionNumber != PKIHeader.CMP_2000
                && versionNumber != PKIHeader.CMP_2021) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.unsupportedVersion,
                    "version " + versionNumber + " not supported");
        }
        assertValueNotNull(header.getSender(), PKIFailureInfo.badDataFormat,
                "Sender");
        assertValueNotNull(header.getRecipient(), PKIFailureInfo.badDataFormat,
                "Recipient");
        assertMinimalLengtOfOctetString(header.getTransactionID(), 16,
                "transactionID");
        assertMinimalLengtOfOctetString(header.getSenderNonce(), 16,
                "senderNonce");
        return extractCertProfile(header);
    }

    private void assertMinimalLengtOfOctetString(final ASN1OctetString ostring,
            final int minimalLength, final String fieldName)
            throws CmpValidationException {
        if (ostring == null) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badDataFormat,
                    "mandatory " + fieldName + " missing");
        }
        if (ostring.getOctets().length < minimalLength) {
            throw new CmpValidationException(interfaceName,
                    PKIFailureInfo.badRequest,
                    "used " + fieldName + " too short");
        }
    }

    private void assertValueNotNull(final Object value, final int failInfo,
            final String fieldName) throws CmpValidationException {
        if (Objects.isNull(value)) {
            throw new CmpValidationException(interfaceName, failInfo,
                    "missing '" + fieldName + "'");
        }
    }

    private String extractCertProfile(final PKIHeader header) {
        if (header == null) {
            return null;
        }
        final InfoTypeAndValue[] generalInfo = header.getGeneralInfo();
        if (generalInfo == null) {
            return null;
        }
        for (final InfoTypeAndValue aktGenInfo : generalInfo) {
            if (aktGenInfo.getInfoType()
                    .equals(CMPObjectIdentifiers.id_it_certProfile)) {
                return ASN1UTF8String.getInstance(aktGenInfo.getInfoValue())
                        .getString();
            }
        }
        return null;
    }
}
