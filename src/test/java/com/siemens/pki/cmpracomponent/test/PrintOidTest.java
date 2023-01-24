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
package com.siemens.pki.cmpracomponent.test;

import com.siemens.pki.cmpracomponent.util.MessageDumper;
import com.siemens.pki.cmpracomponent.util.MessageDumper.OidDescription;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.Ignore;

public class PrintOidTest {
    /**
     * test class to print OIDs and related attributes
     */
    // @Test
    @Ignore
    public void test() {
        final String[] oidStrings = new String[] {
            //
            "1.3.6.1.5.5.7.4.22",
            //
            "1.3.132.1.11.0",
            //
            "1.3.132.1.11.1",
            //
            "1.3.132.1.14.0",
            //
            "1.3.132.1.15.0",
            //
            "1.2.840.10045.3.1.1",
            //
            "1.3.132.0.33",
            //
            "1.3.101.111",
            //
            "2.16.840.1.101.3.4.1.5"
        };
        for (final String str : oidStrings) {
            final OidDescription oidDescriptionForOid =
                    MessageDumper.getOidDescriptionForOid(new ASN1ObjectIdentifier(str));
            System.out.println(oidDescriptionForOid + "->" + oidDescriptionForOid.getBcDeclaration());
        }
    }
}
