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

import static com.siemens.pki.cmpracomponent.util.NullUtil.defaultIfNull;
import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface.ReprotectMode;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpProcessingException;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.protection.ProtectionProvider;
import com.siemens.pki.cmpracomponent.protection.ProtectionProviderFactory;
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * the {@link MsgOutputProtector} sets the right protection for outgoing
 * messages
 */
public class MsgOutputProtector {

    private static final CMPCertificate[] EMPTY_CERTIFCATE_ARRAY = {};

    private static final Logger LOGGER = LoggerFactory.getLogger(MsgOutputProtector.class);

    private final CmpMessageInterface.ReprotectMode reprotectMode;

    private final ProtectionProvider protector;
    private final PersistencyContext persistencyContext;

    private final boolean suppressRedundantExtraCerts;

    private final GeneralName recipient;

    /**
     * ctor
     * @param config             specific configuration
     * @param interfaceName      name of interface used in logging messages
     * @param persistencyContext reference to transaction specific
     *                           {@link PersistencyContext}
     * @throws CmpProcessingException   in case of inconsistent configuration
     * @throws GeneralSecurityException in case of broken configuration
     */
    public MsgOutputProtector(
            final CmpMessageInterface config, final String interfaceName, final PersistencyContext persistencyContext)
            throws CmpProcessingException, GeneralSecurityException {
        this.persistencyContext = persistencyContext;
        suppressRedundantExtraCerts = ConfigLogger.log(
                interfaceName,
                "CmpMessageInterface.getSuppressRedundantExtraCerts()",
                config::getSuppressRedundantExtraCerts);
        reprotectMode =
                ConfigLogger.log(interfaceName, "CmpMessageInterface.getReprotectMode()", config::getReprotectMode);
        recipient = ifNotNull(
                ConfigLogger.logOptional(interfaceName, "CmpMessageInterface.getRecipient()", config::getRecipient),
                rec -> new GeneralName(new X500Name(rec)));
        final CredentialContext outputCredentials = ConfigLogger.logOptional(
                interfaceName, "CmpMessageInterface.getOutputCredentials()", config::getOutputCredentials);
        if (reprotectMode == ReprotectMode.reprotect && outputCredentials == null) {
            throw new CmpProcessingException(
                    interfaceName,
                    PKIFailureInfo.wrongAuthority,
                    "reprotectMode is reprotect, but no output credentials are given");
        }
        protector = ProtectionProviderFactory.createProtectionProvider(outputCredentials, interfaceName);
    }

    /**
     * ctor
     * @param config             specific configuration
     * @param interfaceName      name of interface used in logging messages
     * @throws CmpProcessingException   in case of inconsistent configuration
     * @throws GeneralSecurityException in case of broken configuration
     */
    public MsgOutputProtector(final NestedEndpointContext config, final String interfaceName)
            throws CmpProcessingException, GeneralSecurityException {
        this.persistencyContext = null;
        suppressRedundantExtraCerts = false;
        reprotectMode = ReprotectMode.reprotect;
        recipient = ifNotNull(
                ConfigLogger.logOptional(interfaceName, "NestedEndpointContext.getRecipient()", config::getRecipient),
                rec -> new GeneralName(new X500Name(rec)));
        protector = ProtectionProviderFactory.createProtectionProvider(
                ConfigLogger.logOptional(
                        interfaceName, "NestedEndpointContext.getOutputCredentials()", config::getOutputCredentials),
                interfaceName);
    }

    /**
     * generate and protect a request
     * @param headerProvider the header to use
     * @param body body of new message
     * @return new message
     * @throws Exception in case of error
     */
    public PKIMessage createOutgoingMessage(final HeaderProvider headerProvider, PKIBody body) throws Exception {
        switch (reprotectMode) {
            case reprotect:
            case keep:
                return stripRedundantExtraCerts(PkiMessageGenerator.generateAndProtectMessage(
                        headerProvider, protector, recipient, body, null));
            case strip:
                return PkiMessageGenerator.generateAndProtectMessage(
                        headerProvider, ProtectionProvider.NO_PROTECTION, recipient, body, null);
            default:
                throw new IllegalArgumentException("internal error: invalid reprotectMode mode");
        }
    }

    /**
     * generate and protect a response to a request
     *
     * @param request request to answer
     * @param body    body of new message
     * @return new message
     * @throws Exception in case of error
     */
    public PKIMessage generateAndProtectResponseTo(PKIMessage request, final PKIBody body) throws Exception {
        return stripRedundantExtraCerts(PkiMessageGenerator.generateAndProtectMessage(
                PkiMessageGenerator.buildRespondingHeaderProvider(request), protector, recipient, body, null));
    }
    /**
     * get used ProtectionProvider
     * @return ProtectionProvider
     */
    public ProtectionProvider getProtector() {
        return protector;
    }

    /**
     * protect a PKI message before sending out
     *
     * @param in           message to send
     * @param issuingChain trust chain of issued certificate to add to extracerts or
     *                     <code>null</code>
     * @return protected message ready to send
     * @throws Exception in case of processing error
     */
    public PKIMessage protectOutgoingMessage(final PKIMessage in, final List<CMPCertificate> issuingChain)
            throws Exception {
        switch (reprotectMode) {
            case reprotect:
                return stripRedundantExtraCerts(PkiMessageGenerator.generateAndProtectMessage(
                        PkiMessageGenerator.buildForwardingHeaderProvider(in),
                        protector,
                        recipient,
                        in.getBody(),
                        issuingChain));
            case strip:
                return PkiMessageGenerator.generateAndProtectMessage(
                        PkiMessageGenerator.buildForwardingHeaderProvider(in),
                        ProtectionProvider.NO_PROTECTION,
                        recipient,
                        in.getBody(),
                        issuingChain);
            case keep:
                if (in.getHeader().getProtectionAlg() == null) {
                    // message protection lost during processing, reprotect
                    return stripRedundantExtraCerts(PkiMessageGenerator.generateAndProtectMessage(
                            PkiMessageGenerator.buildForwardingHeaderProvider(in),
                            protector,
                            recipient,
                            in.getBody(),
                            issuingChain));
                }
                final CMPCertificate[] extraCerts = Stream.concat(
                                Arrays.stream(defaultIfNull(in.getExtraCerts(), EMPTY_CERTIFCATE_ARRAY)),
                                defaultIfNull(issuingChain, Collections.emptyList()).stream())
                        .distinct()
                        .toArray(CMPCertificate[]::new);

                return stripRedundantExtraCerts(
                        new PKIMessage(in.getHeader(), in.getBody(), in.getProtection(), extraCerts));
            default:
                throw new IllegalArgumentException("internal error: invalid reprotectMode mode");
        }
    }

    private synchronized PKIMessage stripRedundantExtraCerts(PKIMessage msg) {
        if (!suppressRedundantExtraCerts || persistencyContext == null) {
            return msg;
        }
        final CMPCertificate[] extraCerts = msg.getExtraCerts();
        if (extraCerts == null || extraCerts.length <= 0) {
            LOGGER.debug("no extra certs, no stripping");
            return msg;
        }

        final List<CMPCertificate> extraCertsAsList = new LinkedList<>(Arrays.asList(extraCerts));
        final Set<CMPCertificate> alreadySentExtraCerts = persistencyContext.getAlreadySentExtraCerts();

        if (extraCertsAsList.removeAll(alreadySentExtraCerts)) {
            // were able to drop some extra certs
            if (LOGGER.isDebugEnabled()) {
                // avoid unnecessary string processing, if debug isn't enabled
                LOGGER.debug("drop from " + msg.getExtraCerts().length + " to " + extraCertsAsList.size());
            }
            msg = new PKIMessage(
                    msg.getHeader(),
                    msg.getBody(),
                    msg.getProtection(),
                    extraCertsAsList.isEmpty()
                            ? null
                            : extraCertsAsList.toArray(new CMPCertificate[extraCertsAsList.size()]));
        }
        alreadySentExtraCerts.addAll(extraCertsAsList);
        return msg;
    }
}
