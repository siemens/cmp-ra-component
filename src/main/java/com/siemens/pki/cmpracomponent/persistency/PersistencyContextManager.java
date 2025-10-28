/*
 *  Copyright (c) 2025 Siemens AG
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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.core.Version;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;

/** a manager for {@link PersistencyContext instances} */
public class PersistencyContextManager {

    /**
     * Deserializer for {@link ASN1Object}
     *
     * @param <T> specific type to deserialize
     */
    public static class Asn1ObjectDeserializer<T extends ASN1Object> extends ValueDeserializer<T> {

        private final Class<T> clazz;

        Asn1ObjectDeserializer(final Class<T> clazz) {
            this.clazz = clazz;
        }

        @SuppressWarnings("unchecked")
        @Override
        public T deserialize(final JsonParser p, final DeserializationContext ctxt) {
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
                e.printStackTrace();
            }
            return null;
        }

        @Override
        public Class<T> handledType() {
            return clazz;
        }
    }

    /** Serializer for {@link ASN1Object} */
    public static class Asn1ObjectSerializer extends ValueSerializer<ASN1Object> {
        /** ctor */
        public Asn1ObjectSerializer() {}

        @Override
        public Class<ASN1Object> handledType() {
            return ASN1Object.class;
        }

        @Override
        public void serialize(
                final ASN1Object value, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
            } else {
                try {
                    jsonGenerator.writeBinary(value.getEncoded());
                } catch (JacksonException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
    }

    /** Serializer for {@link PrivateKey}s */
    public static class KeySerializer extends ValueSerializer<PrivateKey> {

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
                final PrivateKey key, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (key == null) {
                jsonGenerator.writeNull();
            }
            try {
                // private key obfuscation
                final Cipher c = Cipher.getInstance(KEY_WRAP_CIPHER);
                c.init(Cipher.WRAP_MODE, secretKey, iv);
                jsonGenerator.writeBinary(c.wrap(key));
            } catch (NoSuchAlgorithmException
                    | NoSuchPaddingException
                    | InvalidKeyException
                    | IllegalBlockSizeException
                    | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
    }

    /** Deserializer for {@link PrivateKey}s */
    public static class PrivateKeyDeserializer extends ValueDeserializer<PrivateKey> {
        private final SecretKeySpec secretKey;

        private PrivateKeyDeserializer(final SecretKeySpec secretKey) {
            this.secretKey = secretKey;
        }

        @Override
        public PrivateKey deserialize(final JsonParser p, final DeserializationContext ctxt) {
            final byte[] binaryValue = p.getBinaryValue();
            if (binaryValue == null || binaryValue.length == 0) {
                return null;
            }
            try {
                final Cipher c = Cipher.getInstance(KEY_WRAP_CIPHER);
                c.init(Cipher.UNWRAP_MODE, secretKey, iv);
                for (final String keyType : new String[] {"RSA", "EC", "Ed448", "Ed25519"}) {
                    try {
                        return (PrivateKey) c.unwrap(binaryValue, keyType, Cipher.PRIVATE_KEY);
                    } catch (final Exception e) {
                        // try next keyType
                    }
                }
                LOGGER.error("cold not load private key");
                return null;
            } catch (final InvalidKeyException
                    | NoSuchAlgorithmException
                    | NoSuchPaddingException
                    | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private static final String KEY_WRAP_CIPHER = "AES/GCM/NoPadding";

    private static final Logger LOGGER = LoggerFactory.getLogger(PersistencyContextManager.class);

    private final JsonMapper.Builder builder = JsonMapper.builder().findAndAddModules();

    private ObjectMapper objectMapper = new ObjectMapper();

    private static final IvParameterSpec iv = new IvParameterSpec("The IV for PrivK".getBytes());

    private final PersistencyInterface wrappedInterface;

    /**
     * ctor
     *
     * @param wrappedInterface external {@link PersistencyInterface} to use for store and load
     */
    public PersistencyContextManager(final PersistencyInterface wrappedInterface) {
        this.wrappedInterface = wrappedInterface;
        final SimpleModule simpleModule = new SimpleModule("BCModule", new Version(1, 0, 0, null, null, null));
        final SecretKeySpec secretKey = new SecretKeySpec(wrappedInterface.getAesKeyForKeyWrapping(), "AES");
        simpleModule.addSerializer(new Asn1ObjectSerializer());
        simpleModule.addSerializer(new KeySerializer(secretKey));
        simpleModule.addDeserializer(ASN1OctetString.class, new Asn1ObjectDeserializer<>(ASN1OctetString.class));
        simpleModule.addDeserializer(CMPCertificate.class, new Asn1ObjectDeserializer<>(CMPCertificate.class));
        simpleModule.addDeserializer(PKIMessage.class, new Asn1ObjectDeserializer<>(PKIMessage.class));
        simpleModule.addDeserializer(PrivateKey.class, new PrivateKeyDeserializer(secretKey));
        builder.addModule(simpleModule);
        objectMapper = builder.build();
    }

    /**
     * forget a {@link PersistencyContext}
     *
     * @param transactionId transactionId of PersistencyContext to forget
     */
    public void clearPersistencyContext(final byte[] transactionId) {
        wrappedInterface.clearLastSavedMessage(transactionId);
    }

    /**
     * write PersistencyContext to external {@link PersistencyInterface}
     *
     * @param context context to write
     * @throws IOException in case of eror
     */
    void flushPersistencyContext(final PersistencyContext context) throws IOException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(context));
        }
        wrappedInterface.saveLastMessage(
                context.getTransactionId(), objectMapper.writeValueAsBytes(context), context.getExpirationTime());
    }

    /**
     * load or create {@link PersistencyContext} related to a transactionId
     *
     * @param transactionId the transactionId addressing the persistency context
     * @return PersistencyContext
     * @throws IOException in case of error
     */
    public PersistencyContext loadCreatePersistencyContext(final byte[] transactionId) throws IOException {
        final PersistencyContext ret = loadPersistencyContext(transactionId);
        if (ret != null) {
            return ret;
        }
        // never seen before, create a new one
        return new PersistencyContext(this, transactionId);
    }

    /**
     * load existing {@link PersistencyContext} related to a transactionId
     *
     * @param transactionId the transactionId addressing the persistency context
     * @return PersistencyContext
     * @throws IOException in case of error
     */
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
}
