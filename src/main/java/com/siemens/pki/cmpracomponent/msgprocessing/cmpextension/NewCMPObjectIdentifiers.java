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
package com.siemens.pki.cmpracomponent.msgprocessing.cmpextension;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;

/**
 * these constants should later go to {@link CMPObjectIdentifiers}
 *
 *
 */
public interface NewCMPObjectIdentifiers extends CMPObjectIdentifiers {

    // TODO drop if BC provides this
    ASN1ObjectIdentifier id_it_crlStatusList =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.22");

    // TODO drop if BC provides this
    ASN1ObjectIdentifier id_it_crls =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.23");

}
