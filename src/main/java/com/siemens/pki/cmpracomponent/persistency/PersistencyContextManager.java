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
package com.siemens.pki.cmpracomponent.persistency;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.siemens.pki.cmpracomponent.configuration.PersistencyInterface;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a manager for {@link PersistencyContext instances}
 */
public class PersistencyContextManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(PersistencyContextManager.class);
    private static final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    private static final IvParameterSpec iv = new IvParameterSpec("The IV for PrivK".getBytes());
    final SimpleModule simpleModule = new SimpleModule("BCModule", new Version(1, 0, 0, null, null, null));
    private final PersistencyInterface wrappedInterface;

    public PersistencyContextManager(final PersistencyInterface wrappedInterface) {
        this.wrappedInterface = wrappedInterface;
        final SecretKeySpec secretKey = new SecretKeySpec(wrappedInterface.getAesKeyForKeyWrapping(), "AES");
        simpleModule.addSerializer(new Asn1ObjectSerializer());
        simpleModule.addSerializer(new KeySerializer(secretKey));
        simpleModule.addDeserializer(CMPCertificate.class, new Asn1ObjectDeserializer<>(CMPCertificate.class));
        simpleModule.addDeserializer(PKIMessage.class, new Asn1ObjectDeserializer<>(PKIMessage.class));
        simpleModule.addDeserializer(PrivateKey.class, new PrivateKeyDeserializer(secretKey));
        objectMapper.registerModule(simpleModule);
    }

    public void clearPersistencyContext(final byte[] transactionId) {
        wrappedInterface.clearLastSavedMessage(transactionId);
    }

    public PersistencyContext loadCreatePersistencyContext(final byte[] transactionId)
            throws IOException, OperatorCreationException {
        final PersistencyContext ret = loadPersistencyContext(transactionId);
        if (ret != null) {
            return ret;
        }
        // never seen before, create a new one
        return new PersistencyContext(this, transactionId);
    }

    public PersistencyContext loadPersistencyContext(final byte[] transactionId) throws IOException {
        final byte[] serializedPersistency = wrappedInterface.getLastSavedMessage(transactionId);
        if (serializedPersistency == null) {
            // transactionId never seen before
            return null;
        }
        // recreate from persistency
        final PersistencyContext ret = objectMapper.readValue(serializedPersistency, PersistencyContext.class);
        ret.setContextManager(this);
        return ret;
    }

    void flushPersistencyContext(final PersistencyContext context) throws IOException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(context));
        }
        wrappedInterface.saveLastMessage(context.getTransactionId(), objectMapper.writeValueAsBytes(context));
    }

    public static class Asn1ObjectDeserializer<T extends ASN1Object> extends JsonDeserializer<T> {

        private final Class<T> clazz;

        Asn1ObjectDeserializer(final Class<T> clazz) {
            this.clazz = clazz;
        }

        @SuppressWarnings("unchecked")
        @Override
        public T deserialize(final JsonParser p, final DeserializationContext ctxt) throws IOException {
            final byte[] binaryValue = p.getBinaryValue();
            if (binaryValue == null || binaryValue.length == 0) {
                return null;
            }
            try {
                return (T) clazz.getMethod("getInstance", Object.class).invoke(null, binaryValue);
            } catch (IllegalAccessException
                    | IllegalArgumentException
                    | InvocationTargetException
                    | NoSuchMethodException
                    | SecurityException e) {
                throw new IOException(e);
            }
        }

        @Override
        public Class<T> handledType() {
            return clazz;
        }
    }

    public static class Asn1ObjectSerializer extends JsonSerializer<ASN1Object> {

        @Override
        public Class<ASN1Object> handledType() {
            return ASN1Object.class;
        }

        @Override
        public void serialize(
                final ASN1Object value, final JsonGenerator jsonGenerator, final SerializerProvider provider)
                throws IOException {
            if (value == null) {
                jsonGenerator.writeNull();
            } else {
                jsonGenerator.writeBinary(value.getEncoded());
            }
        }
    }

    public static class KeySerializer extends JsonSerializer<PrivateKey> {

        private final SecretKeySpec secretKey;

        private KeySerializer(final SecretKeySpec secretKey) {
            this.secretKey = secretKey;
        }

        @Override
        public Class<PrivateKey> handledType() {
            return PrivateKey.class;
        }

        @Override
        public void serialize(
                final PrivateKey key, final JsonGenerator jsonGenerator, final SerializerProvider provider)
                throws IOException {
            if (key == null) {
                jsonGenerator.writeNull();
            }
            try {
                // private key obfuscation
                final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.WRAP_MODE, secretKey, iv);
                jsonGenerator.writeBinary(c.wrap(key));
            } catch (NoSuchAlgorithmException
                    | NoSuchPaddingException
                    | InvalidKeyException
                    | IllegalBlockSizeException
                    | InvalidAlgorithmParameterException e) {
                throw new IOException(e);
            }
        }
    }

    public static class PrivateKeyDeserializer extends JsonDeserializer<PrivateKey> {

        private final SecretKeySpec secretKey;

        private PrivateKeyDeserializer(final SecretKeySpec secretKey) {
            this.secretKey = secretKey;
        }

        @Override
        public PrivateKey deserialize(final JsonParser p, final DeserializationContext ctxt) throws IOException {
            final byte[] binaryValue = p.getBinaryValue();
            if (binaryValue == null || binaryValue.length == 0) {
                return null;
            }
            try {
                final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.UNWRAP_MODE, secretKey, iv);
                for (final String keyType : new String[] {"RSA", "EC", "Ed448", "Ed25519"}) {
                    try {
                        return (PrivateKey) c.unwrap(binaryValue, keyType, Cipher.PRIVATE_KEY);
                    } catch (final Exception e) {
                        continue;
                    }
                }
                LOGGER.error("cold not load private key");
                return null;
            } catch (final InvalidKeyException
                    | NoSuchAlgorithmException
                    | NoSuchPaddingException
                    | InvalidAlgorithmParameterException e1) {
                throw new IOException(e1);
            }
        }
    }
}
