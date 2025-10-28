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
package com.siemens.pki.cmpracomponent.test;

import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpEnrollmentException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageBodyValidator;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.junit.Test;

public class TestMessageBodyValidator {

    private final MessageBodyValidator validatorUnderTest =
            new MessageBodyValidator("test validator", (x, y) -> true, null, null);

    @Test(expected = CmpEnrollmentException.class)
    public void testWrongCertIdInRequest() throws BaseCmpException {
        PKIBody bodyToTest = new PKIBody(
                PKIBody.TYPE_CERT_REQ,
                new CertReqMessages(
                        new CertReqMsg(new CertRequest(77, (new CertTemplateBuilder()).build(), null), null, null)));
        validatorUnderTest.validate(new PKIMessage(null, bodyToTest));
    }

    @Test(expected = CmpValidationException.class)
    public void testWrongCertIdInResponse() throws BaseCmpException {
        PKIBody bodyToTest = new PKIBody(PKIBody.TYPE_CERT_REP, new CertRepMessage(null, new CertResponse[] {
            new CertResponse(new ASN1Integer(77), new PKIStatusInfo(PKIStatus.rejection))
        }));
        validatorUnderTest.validate(new PKIMessage(null, bodyToTest));
    }

    @Test(expected = CmpValidationException.class)
    public void testTwoResponsesInResponse() throws BaseCmpException {
        PKIBody bodyToTest = new PKIBody(PKIBody.TYPE_CERT_REP, new CertRepMessage(null, new CertResponse[] {
            new CertResponse(new ASN1Integer(0), new PKIStatusInfo(PKIStatus.rejection)),
            new CertResponse(new ASN1Integer(0), new PKIStatusInfo(PKIStatus.rejection))
        }));
        validatorUnderTest.validate(new PKIMessage(null, bodyToTest));
    }

    @Test(expected = CmpEnrollmentException.class)
    public void testMissingTemplatInRequeste() throws BaseCmpException {
        PKIBody bodyToTest = new PKIBody(
                PKIBody.TYPE_CERT_REQ, new CertReqMessages(new CertReqMsg(new CertRequest(0, null, null), null, null)));
        validatorUnderTest.validate(new PKIMessage(null, bodyToTest));
    }

    @Test(expected = CmpValidationException.class)
    public void testBrokenPkiStatusInError() throws BaseCmpException {
        PKIBody bodyToTest = new PKIBody(
                PKIBody.TYPE_ERROR,
                new ErrorMsgContent(new PKIStatusInfo(PKIStatus.granted, null, new PKIFailureInfo(77))));
        validatorUnderTest.validate(new PKIMessage(null, bodyToTest));
    }

    @Test
    public void testNegativeRevRep() throws BaseCmpException {
        PKIBody bodyToTest = new PKIBody(
                PKIBody.TYPE_REVOCATION_REP,
                (new RevRepContentBuilder().add(new PKIStatusInfo(PKIStatus.rejection))).build());
        validatorUnderTest.validate(new PKIMessage(null, bodyToTest));
    }
}
