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

package com.siemens.pki.cmpracomponent.protection;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMac;

/**
 * base class for MAC protection provider
 *
 *
 */
public abstract class MacProtection implements ProtectionProvider {

    private AlgorithmIdentifier protectionAlg;

    private WrappedMac protectingMac;

    private final SharedSecretCredentialContext config;

    protected MacProtection(final SharedSecretCredentialContext config) {
        this.config = config;
    }

    @Override
    public List<CMPCertificate> getProtectingExtraCerts() {
        return null;
    }

    @Override
    public AlgorithmIdentifier getProtectionAlg() {
        return protectionAlg;
    }

    @Override
    public synchronized DERBitString getProtectionFor(
            final ProtectedPart protectedPart) throws Exception {
        return new DERBitString(protectingMac
                .calculateMac(protectedPart.getEncoded(ASN1Encoding.DER)));
    }

    @Override
    public GeneralName getSender() {
        return null;
    }

    @Override
    public DEROctetString getSenderKID() {
        return ifNotNull(config.getSenderKID(), DEROctetString::new);
    }

    protected void init(final AlgorithmIdentifier protectionAlg,
            final WrappedMac protectingMac) {
        this.protectingMac = protectingMac;
        this.protectionAlg = protectionAlg;
    }

}
