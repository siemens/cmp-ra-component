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
package com.siemens.pki.cmpracomponent.cmpextension;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;

public interface NewCMPObjectIdentifiers extends CMPObjectIdentifiers {

    /**
     * id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 TBD4}
     */
    ASN1ObjectIdentifier kemBasedMac = new ASN1ObjectIdentifier("1.2.840.113533.7.66.16");

    /**
     * id-it-KemCiphertextInfo OBJECT IDENTIFIER ::= { id-it TBD1 }
     */
    ASN1ObjectIdentifier it_kemCiphertextInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.4.24");
}
