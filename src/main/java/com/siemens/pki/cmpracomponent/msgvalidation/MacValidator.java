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

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;

/**
 * base class for all MAC based validators
 */
public abstract class MacValidator implements ValidatorIF<Void> {

    protected final VerificationContext config;
    private final String interfaceName;

    protected MacValidator(final String interfaceName, final VerificationContext config) {
        this.interfaceName = interfaceName;
        this.config = config;
    }

    protected String getInterfaceName() {
        return interfaceName;
    }

    protected byte[] getSharedSecret(final PKIHeader header) throws CmpValidationException {
        final byte[] passwordAsBytes =
                config.getSharedSecret(ifNotNull(header.getSenderKID(), ASN1OctetString::getOctets));

        if (passwordAsBytes == null) {
            throw new CmpValidationException(
                    getInterfaceName(),
                    PKIFailureInfo.notAuthorized,
                    "message is password protected but no shared secret is provided");
        }
        return passwordAsBytes;
    }
}
