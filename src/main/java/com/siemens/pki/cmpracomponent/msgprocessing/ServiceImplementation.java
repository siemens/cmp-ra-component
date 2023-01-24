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

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.configuration.GetRootCaCertificateUpdateHandler.RootCaCertificateUpdateResponse;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.protection.ProtectionProviderFactory;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

/**
 * implementation of a GENM service handler
 */
class ServiceImplementation {

    private static final String INTERFACE_NAME = "GENM service";
    private final Configuration config;

    /**
     * @param config specific configuration
     * @throws Exception in case of error
     */
    ServiceImplementation(final Configuration config) throws Exception {
        this.config = config;
    }

    private String[] generalNamesToStrings(final GeneralNames generalNames) {
        return Arrays.stream(generalNames.getNames())
                .map(GeneralName::getName)
                .map(ASN1Encodable::toString)
                .toArray(String[]::new);
    }

    private PKIBody handleGetRootCaCertificateUpdate(
            final InfoTypeAndValue itav, final GetRootCaCertificateUpdateHandler messageHandler)
            throws CertificateException {
        final CMPCertificate oldRoot = ifNotNull(itav.getInfoValue(), CMPCertificate::getInstance);
        final RootCaCertificateUpdateResponse response =
                messageHandler.getRootCaCertificateUpdate(ifNotNull(oldRoot, CertUtility::asX509Certificate));
        if (response != null && response.getNewWithNew() != null) {
            final X509Certificate newWithNew = response.getNewWithNew();
            final X509Certificate newWithOld = response.getNewWithOld();
            final X509Certificate oldWithNew = response.getOldWithNew();
            return new PKIBody(
                    PKIBody.TYPE_GEN_REP,
                    new GenRepContent(new InfoTypeAndValue(
                            CMPObjectIdentifiers.id_it_rootCaKeyUpdate,
                            new RootCaKeyUpdateContent(
                                    ifNotNull(newWithNew, CertUtility::asCmpCertificate),
                                    ifNotNull(newWithOld, CertUtility::asCmpCertificate),
                                    ifNotNull(oldWithNew, CertUtility::asCmpCertificate)))));
        }
        return new PKIBody(
                PKIBody.TYPE_GEN_REP,
                new GenRepContent(new InfoTypeAndValue(CMPObjectIdentifiers.id_it_rootCaKeyUpdate)));
    }

    private PKIBody handleCrlUpdateRetrieval(
            final InfoTypeAndValue itav, final CrlUpdateRetrievalHandler messageHandler) throws CmpProcessingException {
        try {
            final ASN1Encodable value = itav.getInfoValue();
            if (value == null) {
                throw new CmpProcessingException(
                        INTERFACE_NAME,
                        PKIFailureInfo.badMessageCheck,
                        "CRLStatus in Crl Update Retrieval request missing");
            }
            ASN1EncodableVector responseCrl = null;
            for (final ASN1Encodable rawCrlStatus : (ASN1Sequence) value.toASN1Primitive()) {
                final CRLStatus crlStatus = CRLStatus.getInstance(rawCrlStatus.toASN1Primitive());
                final CRLSource crlSource = crlStatus.getSource();
                final String[] issuers = ifNotNull(crlSource.getIssuer(), this::generalNamesToStrings);
                String[] dpnFullName = null;
                String dpnNameRelativeToCRLIssuer = null;
                final DistributionPointName dpn = crlSource.getDpn();
                if (dpn != null) {
                    final ASN1Encodable dpnName = dpn.getName();
                    if (dpnName != null) {
                        final int dpnType = dpn.getType();
                        if (dpnType == DistributionPointName.FULL_NAME) {
                            dpnFullName = generalNamesToStrings(GeneralNames.getInstance(dpnName));
                        } else if (dpnType == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER) {
                            dpnNameRelativeToCRLIssuer = new X500Name(new RDN[] {RDN.getInstance(dpnName)}).toString();
                        }
                    }
                }
                final List<X509CRL> crlsToAdd = messageHandler.getCrls(
                        dpnFullName,
                        dpnNameRelativeToCRLIssuer,
                        issuers,
                        ifNotNull(crlStatus.getThisUpdate(), Time::getDate));
                if (crlsToAdd != null) {
                    if (responseCrl == null) {
                        responseCrl = new ASN1EncodableVector();
                    }
                    crlsToAdd.stream()
                            .map(x -> {
                                try {
                                    return CertificateList.getInstance(x.getEncoded());
                                } catch (final CRLException e) {
                                    throw new RuntimeException(e);
                                }
                            })
                            .forEach(responseCrl::add);
                }
            }
            if (responseCrl == null) {
                return new PKIBody(
                        PKIBody.TYPE_GEN_REP, new GenRepContent(new InfoTypeAndValue(CMPObjectIdentifiers.id_it_crls)));
            }
            return new PKIBody(
                    PKIBody.TYPE_GEN_REP,
                    new GenRepContent(
                            new InfoTypeAndValue(CMPObjectIdentifiers.id_it_crls, new DERSequence(responseCrl))));
        } catch (final RuntimeException e) {
            final Throwable cause = e.getCause();
            throw new CmpProcessingException(INTERFACE_NAME, PKIFailureInfo.systemFailure, cause != null ? cause : e);
        }
    }

    private PKIBody handleGetCaCertificates(
            final ASN1ObjectIdentifier infoType, final GetCaCertificatesHandler messageHandler)
            throws CertificateException {
        final List<X509Certificate> caCertificates = messageHandler.getCaCertificates();
        if (caCertificates != null) {
            final CMPCertificate[] certificates = CertUtility.asCmpCertificates(caCertificates);
            return new PKIBody(
                    PKIBody.TYPE_GEN_REP,
                    new GenRepContent(new InfoTypeAndValue(infoType, new DERSequence(certificates))));
        }
        return new PKIBody(PKIBody.TYPE_GEN_REP, new GenRepContent(new InfoTypeAndValue(infoType)));
    }

    private PKIBody handleGetCertificateRequestTemplate(
            final ASN1ObjectIdentifier infoType, final GetCertificateRequestTemplateHandler messageHandler)
            throws IOException {
        final byte[] template = messageHandler.getCertificateRequestTemplate();
        if (template != null) {
            return new PKIBody(
                    PKIBody.TYPE_GEN_REP,
                    new GenRepContent(new InfoTypeAndValue(infoType, ASN1Primitive.fromByteArray(template))));
        }
        return new PKIBody(PKIBody.TYPE_GEN_REP, new GenRepContent(new InfoTypeAndValue(infoType)));
    }

    protected PKIMessage handleValidatedInputMessage(final PKIMessage msg, final PersistencyContext persistencyContext)
            throws BaseCmpException {
        try {
            final InfoTypeAndValue itav = ((GenMsgContent) msg.getBody().getContent()).toInfoTypeAndValueArray()[0];
            final ASN1ObjectIdentifier infoType = itav.getInfoType();

            final SupportMessageHandlerInterface messageHandler =
                    config.getSupportMessageHandler(persistencyContext.getCertProfile(), infoType.getId());
            if (messageHandler == null) {
                return null;
            }
            PKIBody body = null;
            if (messageHandler instanceof GetCaCertificatesHandler) {
                body = handleGetCaCertificates(infoType, (GetCaCertificatesHandler) messageHandler);
            } else if (messageHandler instanceof GetCertificateRequestTemplateHandler) {
                body = handleGetCertificateRequestTemplate(
                        infoType, (GetCertificateRequestTemplateHandler) messageHandler);
            } else if (messageHandler instanceof GetRootCaCertificateUpdateHandler) {
                body = handleGetRootCaCertificateUpdate(itav, (GetRootCaCertificateUpdateHandler) messageHandler);
            } else if (messageHandler instanceof CrlUpdateRetrievalHandler) {
                body = handleCrlUpdateRetrieval(itav, (CrlUpdateRetrievalHandler) messageHandler);
            } else {
                throw new CmpProcessingException(INTERFACE_NAME, PKIFailureInfo.systemFailure, "internal error");
            }
            if (body == null) {
                // no specific processing found, return empty response
                body = new PKIBody(PKIBody.TYPE_GEN_REP, new GenRepContent(new InfoTypeAndValue(infoType)));
            }
            return PkiMessageGenerator.generateAndProtectMessage(
                    PkiMessageGenerator.buildRespondingHeaderProvider(msg),
                    ProtectionProviderFactory.createProtectionProvider(config.getDownstreamConfiguration(
                                    ifNotNull(persistencyContext, PersistencyContext::getCertProfile), body.getType())
                            .getOutputCredentials()),
                    body);
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception e) {
            throw new CmpProcessingException(INTERFACE_NAME, e);
        }
    }
}
