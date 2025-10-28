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
package com.siemens.pki.cmpracomponent.util;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.Version;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.cfg.MapperConfig;
import tools.jackson.databind.introspect.AnnotatedMember;
import tools.jackson.databind.introspect.JacksonAnnotationIntrospector;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.dataformat.yaml.YAMLMapper;

/** A utility class providing functions for dumping messages in JSON/YAML format. */
public class JsonYamlMessageDumper {

    private static ObjectMapper jsonMapper;

    private static ObjectMapper yamlMapper;

    /** Serializer for {@link InputStream} */
    private static class InputStreamSerializer extends ValueSerializer<InputStream> {
        /** */
        @Override
        public Class<InputStream> handledType() {
            return InputStream.class;
        }

        @Override
        public void serialize(
                final InputStream value, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            try {
                jsonGenerator.writeBinary(value.readAllBytes());
            } catch (JacksonException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    /** Serializer for {@link PKIBody} */
    private static class PKIBodySerializer extends ValueSerializer<PKIBody> {

        @Override
        public Class<PKIBody> handledType() {
            return PKIBody.class;
        }

        @Override
        public void serialize(
                final PKIBody value, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            jsonGenerator.writeStartObject();
            jsonGenerator.writeStringProperty("type", MessageDumper.msgTypeAsString(value));
            jsonGenerator.writeStringProperty(
                    "ContentClass", value.getContent().getClass().getSimpleName());
            jsonGenerator.writePOJOProperty("content", value.getContent());
            jsonGenerator.writeEndObject();
        }
    }

    /** Serializer for {@link PKIStatusInfo} */
    private static class PKIStatusInfoSerializer extends ValueSerializer<PKIStatusInfo> {

        private static final String[] STATUS_STRING = new String[] {
            "GRANTED",
            "GRANTED_WITH_MODS",
            "REJECTION",
            "WAITING",
            "REVOCATION_WARNING",
            "REVOCATION_NOTIFICATION ",
            "KEY_UPDATE_WARNING"
        };

        @Override
        public Class<PKIStatusInfo> handledType() {
            return PKIStatusInfo.class;
        }

        @Override
        public void serialize(
                final PKIStatusInfo value, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            jsonGenerator.writeStartObject();
            jsonGenerator.writeStringProperty(
                    "status", STATUS_STRING[value.getStatus().intValue()]);
            if (value.getStatusString() != null) {
                jsonGenerator.writePOJOProperty("statusString", value.getStatusString());
            }
            if (value.getFailInfo() != null) {
                jsonGenerator.writePOJOProperty("failInfo", value.getFailInfo());
            }
            jsonGenerator.writeEndObject();
        }
    }

    /** Serializer for {@link PollRepContent} */
    private static class PollRepContentSeralizer extends ValueSerializer<PollRepContent> {

        @Override
        public Class<PollRepContent> handledType() {
            return PollRepContent.class;
        }

        class PollRepContentWrapper {
            public PollRepContentWrapper(PollRepContent wrapped) {
                this.wrapped = wrapped;
            }

            private final PollRepContent wrapped;

            public Entry[] getEntries() {
                int size = wrapped.size();
                Entry[] ret = new Entry[size];
                for (int i = 0; i < size; i++) {
                    ret[i] = new Entry(i);
                }
                return ret;
            }

            @SuppressWarnings("unused")
            class Entry {
                private final int index;

                public Entry(int index) {
                    super();
                    this.index = index;
                }

                public ASN1Integer getCertReqId() {
                    return wrapped.getCertReqId(index);
                }

                public ASN1Integer getCheckAfter() {
                    return wrapped.getCheckAfter(index);
                }

                public PKIFreeText getReason() {
                    return wrapped.getReason(index);
                }
            }
        }

        @Override
        public void serialize(
                final PollRepContent value, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            jsonGenerator.writePOJO(new PollRepContentWrapper(value).getEntries());
        }
    }

    /** Serializer for {@link Extensions} */
    private static class ExtensionsSeralizer extends ValueSerializer<Extensions> {

        @Override
        public Class<Extensions> handledType() {
            return Extensions.class;
        }

        class ExtensionsWrapper {
            public ExtensionsWrapper(Extensions wrapped) {
                this.wrapped = wrapped;
            }

            private final Extensions wrapped;

            public List<Extension> getEntries() {
                return Arrays.stream(wrapped.getExtensionOIDs())
                        .map(wrapped::getExtension)
                        .toList();
            }
        }

        @Override
        public void serialize(
                final Extensions value, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            jsonGenerator.writePOJO(new ExtensionsWrapper(value).getEntries());
        }
    }

    private static class PKIFreeTextSerializer extends ValueSerializer<PKIFreeText> {

        @Override
        public Class<PKIFreeText> handledType() {
            return PKIFreeText.class;
        }

        @Override
        public void serialize(
                final PKIFreeText value, final JsonGenerator jsonGenerator, final SerializationContext provider) {

            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            int size = value.size();
            jsonGenerator.writeStartArray();
            for (int i = 0; i < size; i++) {
                jsonGenerator.writeObjectPropertyStart(value.getStringAtUTF8(i).toString());
            }
            jsonGenerator.writeEndArray();
        }
    }

    /** generic toString Serializer */
    private static class GenericSerializer<T> extends ValueSerializer<T> {

        private final Class<T> handledType;

        private final Function<T, String> mapToString;

        private GenericSerializer(Class<T> handledType) {
            this.handledType = handledType;
            mapToString = T::toString;
        }

        private GenericSerializer(Class<T> handledType, Function<T, String> mapToString) {
            this.handledType = handledType;
            this.mapToString = mapToString;
        }

        @Override
        public Class<T> handledType() {
            return handledType;
        }

        @Override
        public void serialize(final T value, final JsonGenerator jsonGenerator, final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            jsonGenerator.writeString(mapToString.apply(value));
        }
    }

    /** Serializer for {@link SubjectPublicKeyInfoSerializer} */
    private static class SubjectPublicKeyInfoSerializer extends ValueSerializer<SubjectPublicKeyInfo> {

        @Override
        public Class<SubjectPublicKeyInfo> handledType() {
            return SubjectPublicKeyInfo.class;
        }

        @Override
        public void serialize(
                final SubjectPublicKeyInfo value,
                final JsonGenerator jsonGenerator,
                final SerializationContext provider) {
            if (value == null) {
                jsonGenerator.writeNull();
                return;
            }
            jsonGenerator.writeStartObject();
            jsonGenerator.writeStringProperty(
                    "Algorithm",
                    MessageDumper.getOidDescriptionForOid(value.getAlgorithm().getAlgorithm())
                            .toString());
            try {
                ASN1Primitive parsedKey = value.parsePublicKey();
                jsonGenerator.writePOJOProperty("ParsedKey", parsedKey);
            } catch (IOException ex) {
                jsonGenerator.writePOJOProperty("UnparsedKeyData", value.getPublicKeyData());
            }
            jsonGenerator.writeEndObject();
        }
    }

    /**
     * Dump PKI message in JSON format.
     *
     * @param msg PKI message to be dumped
     * @return JSON representation of the PKI message
     */
    public static final String dumpPkiMessageAsJson(final PKIMessage msg) {
        if (msg == null) {
            return "<null>";
        }
        try {
            return getJsonMapper().writeValueAsString(msg);
        } catch (JacksonException e) {
            return e.getLocalizedMessage();
        }
    }

    /**
     * Dump PKI message in YAML format.
     *
     * @param msg PKI message to be dumped
     * @return YAML representation of the PKI message
     */
    public static final String dumpPkiMessageAsYaml(final PKIMessage msg) {
        if (msg == null) {
            return "<null>";
        }
        try {
            return getYamlMapper().writeValueAsString(msg);
        } catch (JacksonException e) {
            return e.getLocalizedMessage();
        }
    }

    private static ObjectMapper initMapper(MapperBuilder<?, ?> builder) {
        final SimpleModule simpleModule = new SimpleModule("Dump", new Version(1, 0, 0, null, null, null));
        simpleModule.addSerializer(new PKIBodySerializer());
        simpleModule.addSerializer(new SubjectPublicKeyInfoSerializer());
        simpleModule.addSerializer(new PKIFreeTextSerializer());
        simpleModule.addSerializer(new PKIStatusInfoSerializer());
        simpleModule.addSerializer(new PollRepContentSeralizer());
        simpleModule.addSerializer(new ExtensionsSeralizer());
        simpleModule.addSerializer(new InputStreamSerializer());
        simpleModule.addSerializer(new GenericSerializer<>(ASN1Primitive.class));
        simpleModule.addSerializer(new GenericSerializer<>(GeneralName.class));
        simpleModule.addSerializer(new GenericSerializer<>(Number.class));
        simpleModule.addSerializer(new GenericSerializer<>(CharSequence.class));
        simpleModule.addSerializer(new GenericSerializer<>(X500Name.class));
        simpleModule.addSerializer(new GenericSerializer<>(Date.class));
        simpleModule.addSerializer(new GenericSerializer<>(ASN1GeneralizedTime.class, a -> {
            try {
                return a.getDate().toString();
            } catch (ParseException e) {
                return e.getLocalizedMessage();
            }
        }));
        simpleModule.addSerializer(
                new GenericSerializer<>(ASN1ObjectIdentifier.class, a -> MessageDumper.getOidDescriptionForOid(a)
                        .toString()));
        simpleModule.addSerializer(
                new GenericSerializer<>(ASN1Enumerated.class, a -> a.getValue().toString()));
        JsonMapper.Builder jbuilder = JsonMapper.builder().findAndAddModules();
        jbuilder.addModule(simpleModule);

        return builder.enable(MapperFeature.DETECT_PARAMETER_NAMES)
                .enable(SerializationFeature.INDENT_OUTPUT)
                .configure(SerializationFeature.WRITE_SELF_REFERENCES_AS_NULL, true)
                .configure(SerializationFeature.FAIL_ON_SELF_REFERENCES, false)
                .configure(SerializationFeature.FAIL_ON_UNWRAPPED_TYPE_IDENTIFIERS, true)
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
                .changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(Include.NON_NULL))
                .addModule(simpleModule)
                // .serializationInclusion(Include.NON_NULL)
                .annotationIntrospector(new JacksonAnnotationIntrospector() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public boolean hasIgnoreMarker(MapperConfig<?> config, AnnotatedMember member) {
                        return member.getDeclaringClass() == ASN1Object.class || super.hasIgnoreMarker(config, member);
                    }

                    @Override
                    public String findImplicitPropertyName(MapperConfig<?> config, AnnotatedMember member) {
                        String methodName = member.getName();
                        if (methodName != null && methodName.startsWith("to") && methodName.endsWith("Array")) {
                            return methodName.substring(2, methodName.length() - 5);
                        }
                        return super.findImplicitPropertyName(config, member);
                    }
                })
                .build();
    }

    private static ObjectMapper getJsonMapper() {
        if (jsonMapper == null) {
            jsonMapper = initMapper(JsonMapper.builder());
        }
        return jsonMapper;
    }

    private static ObjectMapper getYamlMapper() {
        if (yamlMapper == null) {
            yamlMapper = initMapper(YAMLMapper.builder());
        }
        return yamlMapper;
    }

    private JsonYamlMessageDumper() {}
}
