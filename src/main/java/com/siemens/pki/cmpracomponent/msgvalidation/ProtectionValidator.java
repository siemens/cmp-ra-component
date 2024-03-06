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

import com.siemens.pki.cmpracomponent.cmpextension.NewCMPObjectIdentifiers;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.msggeneration.HeaderProvider;
import com.siemens.pki.cmpracomponent.persistency.InitialKemContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext.InterfaceContext;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class validates the signature or password based protection of all
 * incoming messages and generates proper error responses on failed validation.
 */
public class ProtectionValidator implements ValidatorIF<Void> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProtectionValidator.class);

    private final String interfaceName;

    private final VerificationContext config;

    private final PersistencyContext persistencyContext;

    private final InterfaceContext interfaceContext;

    /**
     * @param interfaceName      interface name used in error messages
     * @param config             specific configuration
     * @param persistencyContext persistency
     * @param interfaceContext
     */
    public ProtectionValidator(
            final String interfaceName,
            final VerificationContext config,
            PersistencyContext persistencyContext,
            InterfaceContext interfaceContext) {
        this.interfaceName = interfaceName;
        this.config = config;
        this.persistencyContext = persistencyContext;
        this.interfaceContext = interfaceContext;
    }

    /**
     *
     * @return GeneralInfo (KemCiphertextInfo) to be used in CMP header.
     * @throws Exception Exception in case of error
     */
    public InfoTypeAndValue getGeneralInfo(HeaderProvider headerProvider) throws Exception {
        final PublicKey kemPubkey = config.getKemPubkey();
        if (kemPubkey == null) {
            return null;
        }
        InitialKemContext initialKemContext = persistencyContext.getInitialKemContext(interfaceContext);
        if (initialKemContext != null) {
            // it_kemCiphertextInfo already known and shared
            return null;
        }
        initialKemContext = new InitialKemContext(
                headerProvider.getTransactionID(),
                headerProvider.getSenderNonce(),
                headerProvider.getRecipNonce(),
                kemPubkey);
        LOGGER.debug("initialKemContext=\n" + initialKemContext);
        persistencyContext.setInitialKemContext(initialKemContext, interfaceContext);
        return new InfoTypeAndValue(
                NewCMPObjectIdentifiers.it_kemCiphertextInfo, initialKemContext.getCiphertextInfo());
    }

    /**
     * Check a incoming message for correct protection
     *
     * @param message message to check
     *
     * @throws CmpProcessingException in case of error or failed protection
     *                                validation
     */
    @Override
    public Void validate(final PKIMessage message, PersistencyContext.InterfaceContext interfaceContext)
            throws BaseCmpException {
        if (config == null) {
            // protection validation is not needed
            return null;
        }
        final ASN1BitString protection = message.getProtection();
        final AlgorithmIdentifier protectionAlg = message.getHeader().getProtectionAlg();
        if (protection == null || protectionAlg == null) {
            switch (message.getBody().getType()) {
                case PKIBody.TYPE_ERROR:
                case PKIBody.TYPE_CONFIRM:
                case PKIBody.TYPE_REVOCATION_REP:
                    // some messages are allowed to be unprotected or protected
                    // in a strange way
                    LOGGER.warn("broken protection ignored for " + MessageDumper.msgTypeAsString(message.getBody()));
                    return null;
                default:
                    throw new CmpValidationException(
                            interfaceName,
                            PKIFailureInfo.notAuthorized,
                            "message is incomplete protected but protection is required");
            }
        }
        if (CMPObjectIdentifiers.passwordBasedMac.equals(protectionAlg.getAlgorithm())) {
            new PasswordBasedMacValidator(interfaceName, config).validate(message, interfaceContext);
        } else if (PKCSObjectIdentifiers.id_PBMAC1.equals(protectionAlg.getAlgorithm())) {
            new PBMAC1ProtectionValidator(interfaceName, config).validate(message, interfaceContext);
        } else if (NewCMPObjectIdentifiers.kemBasedMac.equals(protectionAlg.getAlgorithm())) {
            new KEMProtectionValidator(interfaceName, config, persistencyContext).validate(message, interfaceContext);
        } else {
            new SignatureProtectionValidator(interfaceName, config).validate(message, interfaceContext);
        }
        return null;
    }
}
