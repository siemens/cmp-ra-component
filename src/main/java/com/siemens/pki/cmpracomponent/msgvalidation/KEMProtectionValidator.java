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
package com.siemens.pki.cmpracomponent.msgvalidation;

import com.siemens.pki.cmpracomponent.cmpextension.KemBMParameter;
import com.siemens.pki.cmpracomponent.cmpextension.KemOtherInfo;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.KdfFunction;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMac;
import com.siemens.pki.cmpracomponent.cryptoservices.WrappedMacFactory;
import com.siemens.pki.cmpracomponent.persistency.InitialKemContext;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;

public class KEMProtectionValidator implements ValidatorIF<Void> {

    private final PersistencyContext persistencyContext;
    private final String interfaceName;

    public KEMProtectionValidator(
            String interfaceName, VerificationContext config, PersistencyContext persistencyContext) {
        this.interfaceName = interfaceName;
        this.persistencyContext = persistencyContext;
    }

    @Override
    public Void validate(final PKIMessage message, PersistencyContext.InterfaceContext interfaceContext)
            throws BaseCmpException {
        try {
            final PKIHeader header = message.getHeader();

            final InitialKemContext initialKemContext = persistencyContext.getInitialKemContext(interfaceContext);
            if (initialKemContext == null) {
                throw new CmpProcessingException(interfaceName, PKIFailureInfo.badMessageCheck, "KEM context missing");
            }

            final KemBMParameter kemBmpParameter =
                    KemBMParameter.getInstance(header.getProtectionAlg().getParameters());
            final int keyLen = kemBmpParameter.getLen().intPositiveValueExact();

            final KemOtherInfo kemOtherInfo = initialKemContext.buildKemOtherInfo(keyLen, kemBmpParameter.getMac());

            final KdfFunction kdf = KdfFunction.getKdfInstance(kemBmpParameter.getKdf());
            final byte[] sharedSecret = initialKemContext.getSharedSecret();
            if (sharedSecret == null) {
                throw new CmpValidationException(
                        interfaceName,
                        PKIFailureInfo.badMessageCheck,
                        "could not calculate shared secret, KEM protection check failed");
            }
            final SecretKey key = kdf.deriveKey(sharedSecret, keyLen, null, kemOtherInfo.getEncoded());

            final WrappedMac mac = WrappedMacFactory.createWrappedMac(kemBmpParameter.getMac(), key.getEncoded());
            final byte[] protectedBytes = new ProtectedPart(header, message.getBody()).getEncoded(ASN1Encoding.DER);
            final byte[] recalculatedProtection = mac.calculateMac(protectedBytes);

            final byte[] protectionBytes = message.getProtection().getBytes();
            if (!Arrays.equals(recalculatedProtection, protectionBytes)) {
                throw new CmpValidationException(
                        interfaceName, PKIFailureInfo.badMessageCheck, "KEM protection check failed");
            }
        } catch (final BaseCmpException cex) {
            throw cex;
        } catch (final Exception ex) {
            throw new CmpProcessingException(interfaceName, PKIFailureInfo.badMessageCheck, ex.getLocalizedMessage());
        }
        return null;
    }
}
