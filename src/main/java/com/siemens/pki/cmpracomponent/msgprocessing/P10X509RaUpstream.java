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
package com.siemens.pki.cmpracomponent.msgprocessing;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.util.CmpFuncEx;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class P10X509RaUpstream implements RaUpstream {

    private static final String INTERFACE_NAME = "P10X509 upstream";

    private static final Logger LOGGER = LoggerFactory.getLogger(P10X509RaUpstream.class);

    private final CmpFuncEx<CertificationRequest, CMPCertificate> upstreamMsgHandler;

    P10X509RaUpstream(final CmpFuncEx<CertificationRequest, CMPCertificate> upstreamExchange) {
        this.upstreamMsgHandler = upstreamExchange;
    }

    @Override
    public PKIMessage handleRequest(final PKIMessage in, final PersistencyContext pesistencyContext)
            throws BaseCmpException {
        if (upstreamMsgHandler == null) {
            throw new CmpProcessingException(
                    INTERFACE_NAME, PKIFailureInfo.systemUnavail, "no upstream interface available");
        }
        try {
            switch (in.getBody().getType()) {
                case PKIBody.TYPE_CERT_CONFIRM:
                    return PkiMessageGenerator.generateUnprotectMessage(
                            PkiMessageGenerator.buildRespondingHeaderProvider(in),
                            PkiMessageGenerator.generatePkiConfirmBody());

                case PKIBody.TYPE_P10_CERT_REQ:
                    pesistencyContext.setInitialRequest(in);

                    final CertificationRequest certificationRequest =
                            (CertificationRequest) in.getBody().getContent();
                    final CMPCertificate responseFromUpstream = upstreamMsgHandler.apply(
                            certificationRequest,
                            pesistencyContext.getCertProfile(),
                            pesistencyContext.getRequestType());
                    if (responseFromUpstream == null) {
                        throw new CmpProcessingException(
                                INTERFACE_NAME, PKIFailureInfo.systemUnavail, "got no response from upstream");
                    }

                    return PkiMessageGenerator.generateAndProtectMessage(
                            PkiMessageGenerator.buildRespondingHeaderProvider(in),
                            ProtectionProvider.NO_PROTECTION,
                            PkiMessageGenerator.generateIpCpKupBody(PKIBody.TYPE_CERT_REP, responseFromUpstream));
                default:
                    throw new CmpValidationException(
                            INTERFACE_NAME,
                            PKIFailureInfo.badMessageCheck,
                            "message " + MessageDumper.msgTypeAsString(in) + " not supported ");
            }
        } catch (final Exception e) {
            LOGGER.error("fatal error at" + INTERFACE_NAME);
            throw new CmpProcessingException("fatal error at" + INTERFACE_NAME, e);
        }
    }
}
