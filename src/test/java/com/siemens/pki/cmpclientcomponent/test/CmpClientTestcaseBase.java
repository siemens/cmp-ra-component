package com.siemens.pki.cmpclientcomponent.test;

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

import static org.junit.Assert.fail;

import com.siemens.pki.cmpclientcomponent.configuration.ClientContext;
import com.siemens.pki.cmpclientcomponent.main.CmpClient;
import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.test.framework.CmpCaMock;
import com.siemens.pki.cmpracomponent.test.framework.ConfigFileLoader;
import com.siemens.pki.cmpracomponent.test.framework.ConfigurationFactory;
import com.siemens.pki.cmpracomponent.test.framework.PasswordValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.SignatureValidationCredentials;
import com.siemens.pki.cmpracomponent.test.framework.TrustChainAndPrivateKey;
import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class CmpClientTestcaseBase {

    public static final File CONFIG_DIRECTORY = new File("./src/test/java/com/siemens/pki/cmpracomponent/test/config");

    static {
        ConfigFileLoader.setConfigFileBase(CONFIG_DIRECTORY);
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    protected static CmpMessageInterface getPasswordBasedUpstreamconfiguration(
            SharedSecretCredentialContext protection, SignatureValidationCredentials keyValidationCredentials) {
        return new CmpMessageInterface() {

            final PasswordValidationCredentials passwordUpstreamTrust =
                    new PasswordValidationCredentials(protection.getSharedSecret());

            @Override
            public VerificationContext getInputVerification() {
                return new VerificationContext() {
                    @Override
                    public Collection<X509Certificate> getAdditionalCerts() {
                        return keyValidationCredentials.getAdditionalCerts();
                    }

                    @Override
                    public byte[] getSharedSecret(byte[] senderKID) {
                        return passwordUpstreamTrust.getSharedSecret(senderKID);
                    }

                    @Override
                    public Collection<X509Certificate> getTrustedCertificates() {
                        return keyValidationCredentials.getTrustedCertificates();
                    }
                };
            }

            @Override
            public NestedEndpointContext getNestedEndpointContext() {
                return null;
            }

            @Override
            public CredentialContext getOutputCredentials() {
                return protection;
            }

            @Override
            public ReprotectMode getReprotectMode() {
                return ReprotectMode.reprotect;
            }

            @Override
            public boolean getSuppressRedundantExtraCerts() {
                return false;
            }

            @Override
            public boolean isCacheExtraCerts() {
                return false;
            }

            @Override
            public boolean isMessageTimeDeviationAllowed(final long deviation) {
                return deviation < 10;
            }
        };
    }

    protected static CmpMessageInterface getSignatureBasedUpstreamconfiguration(final String upstreamTrustPath) {
        return new CmpMessageInterface() {

            final SignatureValidationCredentials upstreamTrust =
                    new SignatureValidationCredentials(upstreamTrustPath, null);

            @Override
            public VerificationContext getInputVerification() {
                return upstreamTrust;
            }

            @Override
            public NestedEndpointContext getNestedEndpointContext() {
                return null;
            }

            @Override
            public CredentialContext getOutputCredentials() {
                try {
                    return ConfigurationFactory.getEeSignaturebasedCredentials();
                } catch (final Exception e) {
                    fail(e.getLocalizedMessage());
                    return null;
                }
            }

            @Override
            public ReprotectMode getReprotectMode() {
                return ReprotectMode.reprotect;
            }

            @Override
            public boolean getSuppressRedundantExtraCerts() {
                return false;
            }

            @Override
            public boolean isCacheExtraCerts() {
                return false;
            }

            @Override
            public boolean isMessageTimeDeviationAllowed(final long deviation) {
                return deviation < 10;
            }
        };
    }

    protected UpstreamExchange upstreamExchange;

    protected CmpClient getPasswordBasedCmpClient(
            String certProfile,
            final ClientContext clientContext,
            SharedSecretCredentialContext protection,
            SignatureValidationCredentials keyValidationCredentials)
            throws Exception {
        return new CmpClient(
                certProfile,
                getUpstreamExchange(),
                getPasswordBasedUpstreamconfiguration(protection, keyValidationCredentials),
                clientContext);
    }

    protected CmpClient getSignatureBasedCmpClient(
            String certProfile, final ClientContext clientContext, final String upstreamTrustPath) throws Exception {
        return new CmpClient(
                certProfile,
                getUpstreamExchange(),
                getSignatureBasedUpstreamconfiguration(upstreamTrustPath),
                clientContext);
    }

    protected UpstreamExchange getUpstreamExchange() {
        return upstreamExchange;
    }

    protected UpstreamExchange launchCmpCaAndRa(final Configuration raConfig) throws Exception {
        return launchCmpRa(
                raConfig,
                new CmpCaMock("credentials/ENROLL_Keystore.p12", "credentials/CMP_CA_Keystore.p12")
                        ::sendReceiveMessage);
    }

    protected UpstreamExchange launchCmpCaAndRa(
            TrustChainAndPrivateKey enrollmentCredential, final Configuration raConfig) throws Exception {
        return launchCmpRa(
                raConfig, new CmpCaMock(enrollmentCredential, "credentials/CMP_CA_Keystore.p12")::sendReceiveMessage);
    }

    protected UpstreamExchange launchCmpCaAndRaAndLra(final Configuration raConfig, final Configuration lraConfig)
            throws Exception {
        final UpstreamExchange ra = launchCmpCaAndRa(raConfig);
        final CmpRaInterface lra = CmpRaComponent.instantiateCmpRaComponent(lraConfig, (x, y, z) -> {
            try {
                return ra.sendReceiveMessage(x, y, z);
            } catch (final IOException e) {
                fail(e.getMessage());
                return null;
            }
        });
        upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
            try {
                return lra.processRequest(request);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return upstreamExchange;
    }

    protected UpstreamExchange launchCmpRa(final Configuration config, final UpstreamExchange caMock) throws Exception {
        final CmpRaInterface raComponent = CmpRaComponent.instantiateCmpRaComponent(config, caMock);
        upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
            try {
                return raComponent.processRequest(request);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return upstreamExchange;
    }

    protected UpstreamExchange launchP10X509CaAndRa(final Configuration config) throws Exception {
        return launchP10X509Ra(
                config,
                new CmpCaMock("credentials/ENROLL_Keystore.p12", "credentials/CMP_CA_Keystore.p12")
                        ::processP10CerticateRequest);
    }

    protected UpstreamExchange launchP10X509Ra(
            final Configuration config, final BiFunction<byte[], String, byte[]> caMock) throws Exception {
        final Function<byte[], byte[]> raComponent = CmpRaComponent.instantiateP10X509CmpRaComponent(config, caMock);
        upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
            try {
                return raComponent.apply(request);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
        return upstreamExchange;
    }
}
