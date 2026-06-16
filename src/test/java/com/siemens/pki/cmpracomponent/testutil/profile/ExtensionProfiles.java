/*
 *  Copyright (c) 2026 Siemens AG
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
package com.siemens.pki.cmpracomponent.testutil.profile;

import java.util.List;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

public class ExtensionProfiles {

    public static Extensions eeTlsClientServer(List<GeneralName> sans) throws Exception {
        ExtensionsGenerator g = new ExtensionsGenerator();

        // CA=false
        g.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Typical leaf KU
        g.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement));

        // EKU: server + client auth
        g.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {
            KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth
        }));

        if (sans != null && !sans.isEmpty()) {
            g.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans.toArray(GeneralName[]::new)));
        }

        return g.generate();
    }
}
