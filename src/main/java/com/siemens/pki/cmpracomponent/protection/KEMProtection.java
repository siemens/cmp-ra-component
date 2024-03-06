/*
 *  Copyright (c) 2023 Siemens AG
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
package com.siemens.pki.cmpracomponent.protection;

import com.siemens.pki.cmpracomponent.cmpextension.KemBMParameter;
import com.siemens.pki.cmpracomponent.cmpextension.KemOtherInfo;
import com.siemens.pki.cmpracomponent.cmpextension.NewCMPObjectIdentifiers;
import com.siemens.pki.cmpracomponent.configuration.KEMCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.cryptoservices.KdfFunction;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMac;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMacFactory;
import com.siemens.pki.cmpracomponent.persistency.InitialKemContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext.InterfaceContext;
import com.siemens.pki.cmpracomponent.util.NullUtil;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KEMProtection implements ProtectionProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(KEMProtection.class);
    private final AlgorithmIdentifier kdf;
    private final int keyLen;
    private final AlgorithmIdentifier mac;
    private final PersistencyContext persistencyContext;
    private final InterfaceContext interfaceContext;
    private final PrivateKey privkey;

    private final CMPCertificate[] certChain;

    KEMProtection(
            final KEMCredentialContext config,
            final PersistencyContext persistencyContext,
            final InterfaceContext interfaceContext)
            throws NoSuchAlgorithmException, CertificateException {
        this.interfaceContext = interfaceContext;
        this.persistencyContext = persistencyContext;
        this.privkey = config.getPrivkey();
        this.certChain = NullUtil.ifNotNull(config.getCertificateChain(), CertUtility::asCmpCertificates);
        mac = new AlgorithmIdentifier(AlgorithmHelper.getOidForMac(config.getMacAlgorithm()));
        keyLen = config.getkeyLength();
        kdf = AlgorithmHelper.getKdfOID(config.getKdf());
    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() throws Exception {
        return certChain != null ? Arrays.asList(certChain) : null;
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() {
        return new AlgorithmIdentifier(NewCMPObjectIdentifiers.kemBasedMac, new KemBMParameter(kdf, null, keyLen, mac));
    }

    @Override
    public DERBitString getProtectionFor(ProtectedPart protectedPart) throws Exception {
        final InitialKemContext initialKemContext = persistencyContext.getInitialKemContext(interfaceContext);
        final KemOtherInfo kemOtherInfo = new KemOtherInfo(initialKemContext.getTransactionID(), null);
        final KdfFunction kdf = KdfFunction.getKdfInstance(this.kdf);
        final SecretKey key =
                kdf.deriveKey(initialKemContext.getSharedSecret(privkey), keyLen, null, kemOtherInfo.getEncoded());
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(initialKemContext.toString());
            LOGGER.debug(kemOtherInfo.toString());
            LOGGER.debug("derivedKey: " + Hex.toHexString(key.getEncoded()));
        }
        final WrappedMac mac = WrappedMacFactory.createWrappedMac(this.mac, key.getEncoded());
        return new DERBitString(mac.calculateMac(protectedPart.getEncoded(ASN1Encoding.DER)));
    }

    @Override
    public GeneralName getSender() {
        if (certChain != null && certChain.length > 0) {
            return new GeneralName(certChain[0].getX509v3PKCert().getSubject());
        }
        return null;
    }

    @Override
    public DEROctetString getSenderKID() {
        if (certChain != null && certChain.length > 0) {
            try {
                return CertUtility.extractSubjectKeyIdentifierFromCert(CertUtility.asX509Certificate(certChain[0]));
            } catch (final CertificateException e) {
            }
        }
        return null;
    }

    @Override
    public boolean needsClientInitialKemSetup() {
        return privkey != null;
    }
}
