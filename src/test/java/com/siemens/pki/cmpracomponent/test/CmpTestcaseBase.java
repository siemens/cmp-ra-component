/*
 *  Copyright (c) 2020 Siemens AG
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

import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;

import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.test.framework.CmpCaMock;
import com.siemens.pki.cmpracomponent.test.framework.ConfigFileLoader;

public class CmpTestcaseBase {

    static public final File CONFIG_DIRECTORY = new File(
            "./src/test/java/com/siemens/pki/cmpracomponent/test/config");

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        Security.addProvider(CertUtility.getBouncyCastleProvider());
        ConfigFileLoader.setConfigFileBase(CONFIG_DIRECTORY);
    }

    private Function<PKIMessage, PKIMessage> eeClient;

    protected Function<PKIMessage, PKIMessage> getEeClient() {
        return eeClient;
    }

    protected Function<PKIMessage, PKIMessage> launchCmpCaAndRa(
            final Configuration config)
            throws Exception, GeneralSecurityException, InterruptedException {
        return launchCmpRa(config,
                new CmpCaMock("credentials/ENROLL_Keystore.p12",
                        "credentials/CMP_CA_Keystore.p12")::processCmpRequest);
    }

    protected Function<PKIMessage, PKIMessage> launchCmpCaAndRaAndLra(
            final Configuration raConfig, final Configuration lraConfig)
            throws GeneralSecurityException, InterruptedException, Exception {
        final Function<PKIMessage, PKIMessage> ra = launchCmpCaAndRa(raConfig);
        final CmpRaInterface lra =
                CmpRaComponent.instantiateCmpRaComponent(lraConfig, (x, y) -> {
                    try {
                        return ra.apply(PKIMessage.getInstance(x)).getEncoded();
                    } catch (final IOException e) {
                        fail(e.getMessage());
                        return null;
                    }
                });
        eeClient = req -> {
            try {
                return PKIMessage
                        .getInstance(lra.processRequest(req.getEncoded()));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return eeClient;
    }

    protected Function<PKIMessage, PKIMessage> launchCmpRa(
            final Configuration config,
            final BiFunction<byte[], String, byte[]> caMock)
            throws Exception, GeneralSecurityException, InterruptedException {
        final CmpRaInterface raComponent =
                CmpRaComponent.instantiateCmpRaComponent(config, caMock);
        eeClient = req -> {
            try {
                return PKIMessage.getInstance(
                        raComponent.processRequest(req.getEncoded()));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return eeClient;

    }

    protected Function<PKIMessage, PKIMessage> launchP10X509CaAndRa(
            final Configuration config)
            throws Exception, GeneralSecurityException, InterruptedException {
        return launchP10X509Ra(config, new CmpCaMock(
                "credentials/ENROLL_Keystore.p12",
                "credentials/CMP_CA_Keystore.p12")::processP10CerticateRequest);
    }

    protected Function<PKIMessage, PKIMessage> launchP10X509Ra(
            final Configuration config,
            final BiFunction<byte[], String, byte[]> caMock)
            throws Exception, GeneralSecurityException, InterruptedException {
        final Function<byte[], byte[]> raComponent =
                CmpRaComponent.instantiateP10X509CmpRaComponent(config, caMock);
        eeClient = req -> {
            try {
                return PKIMessage
                        .getInstance(raComponent.apply(req.getEncoded()));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return eeClient;
    }

}
