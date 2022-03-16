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
package com.siemens.pki.cmpracomponent.cryptoservices;

import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.PasswordRecipient;
import org.bouncycastle.cms.PasswordRecipient.PRF;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * utility class to translate between Java JCE Strings, OIDs, {@link Mac},
 * {@link Digest} a.s.o.
 * TODO copy of org.bouncycastle.cms.CMSSignedHelper
 *
 */
public class AlgorithmHelper {

    static class AlgorithmTableEntry<CT> {
        final String javaId;
        final CT cmpId;

        private AlgorithmTableEntry(final String javaId, final CT cmpId) {
            this.javaId = javaId;
            this.cmpId = cmpId;
        }
    }

    abstract static class JavaAlgorithmTable<CT> {
        private static final Logger LOGGER = LoggerFactory
                .getLogger(AlgorithmHelper.JavaAlgorithmTable.class);

        private final Map<String, AlgorithmTableEntry<CT>> wrappedMap =
                new HashMap<>();

        void addEntry(final CT cmpId, final String javaId,
                final String... aliases) {
            final AlgorithmTableEntry<CT> entry =
                    new AlgorithmTableEntry<>(javaId, cmpId);
            wrappedMap.put(normalizeId(javaId), entry);
            for (final String aktId : extractAliases(cmpId)) {
                if (aktId != null) {
                    wrappedMap.put(normalizeId(aktId), entry);
                }
            }
            for (final String aktId : aliases) {
                if (aktId != null) {
                    wrappedMap.put(normalizeId(aktId), entry);
                }
            }
        }

        abstract String[] extractAliases(CT cmpId);

        CT getCmpAlgorithm(final String id) {
            return ifNotNull(wrappedMap.get(normalizeId(id)), x -> x.cmpId);
        }

        String getJavaAlgorithm(final String id) {
            final AlgorithmTableEntry<CT> ret = wrappedMap.get(normalizeId(id));
            if (ret == null) {
                LOGGER.warn("unknown algorithm: " + id);
                return null;
            }
            return ret.javaId;
        }
    }

    static class NameToOidTable extends HashMap<String, ASN1ObjectIdentifier> {

        private static final long serialVersionUID = 1L;

        public ASN1ObjectIdentifier get(final String key) {
            return super.get(normalizeId(key));
        }

        void addAll(final ASN1ObjectIdentifier oid, final String... names) {
            put(oid.toString(), oid);
            for (final String aktName : names) {
                put(normalizeId(aktName), oid);
            }
        }
    }

    private static final DefaultJcaJceHelper HELPER = new DefaultJcaJceHelper();

    private static final JavaAlgorithmTable<PasswordRecipient.PRF> PBKDF2_ALG_NAMES =
            new JavaAlgorithmTable<>() {
                @Override
                String[] extractAliases(final PRF prf) {
                    return new String[] {prf.getName(),
                            prf.getAlgorithmID().getAlgorithm().getId()};
                }
            };

    private static final JavaAlgorithmTable<ASN1ObjectIdentifier> MAC_ALG_OIDS =
            new JavaAlgorithmTable<>() {
                @Override
                String[] extractAliases(final ASN1ObjectIdentifier cmpId) {
                    return new String[] {cmpId.getId()};
                }
            };

    public static final DefaultDigestAlgorithmIdentifierFinder DIG_ALG_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();

    private static final NameToOidTable KEY_AGREEMENT_OIDS =
            new NameToOidTable();

    private static final NameToOidTable KEY_ENCRYPTION_OIDS =
            new NameToOidTable();

    private static final NameToOidTable KEK_OIDS = new NameToOidTable();

    static {

        PBKDF2_ALG_NAMES.addEntry(PasswordRecipient.PRF.HMacSHA1,
                "PBKDF2WITHHMACSHA1", "SHA1", "id-hmacWithSHA1",
                "hmacWithSHA1");
        PBKDF2_ALG_NAMES.addEntry(PasswordRecipient.PRF.HMacSHA224,
                "PBKDF2WITHHMACSHA224", "SHA224", "id-hmacWithSHA224",
                "hmacWithSHA224");
        PBKDF2_ALG_NAMES.addEntry(PasswordRecipient.PRF.HMacSHA256,
                "PBKDF2WITHHMACSHA256", "SHA256", "id-hmacWithSHA256",
                "hmacWithSHA256");
        PBKDF2_ALG_NAMES.addEntry(PasswordRecipient.PRF.HMacSHA384,
                "PBKDF2WITHHMACSHA384", "SHA384", "id-hmacWithSHA384",
                "hmacWithSHA384");
        PBKDF2_ALG_NAMES.addEntry(PasswordRecipient.PRF.HMacSHA512,
                "PBKDF2WITHHMACSHA512", "SHA512", "id-hmacWithSHA512",
                "hmacWithSHA512");

        MAC_ALG_OIDS.addEntry(PKCSObjectIdentifiers.id_hmacWithSHA1, "HMACSHA1",
                "SHA1");
        MAC_ALG_OIDS.addEntry(PKCSObjectIdentifiers.id_hmacWithSHA224,
                "HMACSHA224", "SHA224");
        MAC_ALG_OIDS.addEntry(PKCSObjectIdentifiers.id_hmacWithSHA256,
                "HMACSHA256", "SHA256");
        MAC_ALG_OIDS.addEntry(PKCSObjectIdentifiers.id_hmacWithSHA384,
                "HMACSHA384", "SHA384");
        MAC_ALG_OIDS.addEntry(PKCSObjectIdentifiers.id_hmacWithSHA512,
                "HMACSHA512", "SHA512");
        MAC_ALG_OIDS.addEntry(NISTObjectIdentifiers.id_KmacWithSHAKE128,
                "KmacWithSHAKE128", "SHAKE128");
        MAC_ALG_OIDS.addEntry(NISTObjectIdentifiers.id_KmacWithSHAKE256,
                "KmacWithSHAKE256", "SHAKE256");

        //
        KEY_AGREEMENT_OIDS.addAll(PKCSObjectIdentifiers.id_alg_ESDH,
                "id_alg_ESDH", "ESDH");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme,
                "dhSinglePass-stdDH-sha224kdf-scheme", "ECDH_SHA224KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme,
                "dhSinglePass-stdDH-sha256kdf-scheme", "ECDH_SHA256KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme,
                "dhSinglePass-stdDH-sha384kdf-scheme", "ECDH_SHA384KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme,
                "dhSinglePass-stdDH-sha512kdf-scheme", "ECDH_SHA512KDF");
        //
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme,
                "dhSinglePass_cofactorDH_sha224kdf_scheme", "ECCDH_SHA224KDF",
                "SHA224KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme,
                "dhSinglePass-cofactorDH-sha256kdf-scheme", "ECCDH_SHA256KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme,
                "dhSinglePass-cofactorDH-sha384kdf-scheme", "ECCDH_SHA384KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme,
                "dhSinglePass-cofactorDH-sha512kdf-scheme", "ECCDH_SHA512KDF");
        //
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme,
                "mqvSinglePass_sha224kdf_scheme", "ECMQV_SHA224KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme,
                "mqvSinglePass_sha256kdf_scheme", "ECMQV_SHA256KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme,
                "mqvSinglePass_sha384kdf_scheme", "ECMQV_SHA384KDF");
        KEY_AGREEMENT_OIDS.addAll(
                SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme,
                "mqvSinglePass_sha512kdf_scheme", "ECMQV_SHA512KDF");
        KEY_AGREEMENT_OIDS.addAll(EdECObjectIdentifiers.id_X25519, "id_X25519",
                "X25519");
        KEY_AGREEMENT_OIDS.addAll(EdECObjectIdentifiers.id_X448, "id_X448",
                "X448");
        //
        KEK_OIDS.addAll(CMSAlgorithm.AES128_WRAP, "AES128_WRAP", "AES128");
        KEK_OIDS.addAll(CMSAlgorithm.AES192_WRAP, "AES192_WRAP", "AES192");
        KEK_OIDS.addAll(CMSAlgorithm.AES256_WRAP, "AES256_WRAP", "AES256");
        //
        KEY_ENCRYPTION_OIDS.addAll(CMSAlgorithm.AES128_CBC, "AES128_CBC",
                "AES128");
        KEY_ENCRYPTION_OIDS.addAll(CMSAlgorithm.AES192_CBC, "AES192_CBC",
                "AES192");
        KEY_ENCRYPTION_OIDS.addAll(CMSAlgorithm.AES256_CBC, "AES256_CBC",
                "AES256");

    }

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AlgorithmHelper.class);

    private static final DefaultSignatureAlgorithmIdentifierFinder DEFAULT_SIGNATURE_ALGORITHM_IDENTIFIER_FINDER =
            new DefaultSignatureAlgorithmIdentifierFinder();

    public static char[] convertSharedSecretToPassword(final byte[] password) {
        if (password == null || password.length == 0) {
            return new char[0];
        }
        final char[] ret = new char[password.length];
        for (int i = 0; i < password.length; i++) {
            ret[i] = (char) password[i];
        }
        return ret;
    }

    public static AlgorithmIdentifier findDigestAlgoritm(
            final MessageDigest dig) {
        return DIG_ALG_FINDER.find(dig.getAlgorithm().toUpperCase());
    }

    /**
     * Get Algorithm OID for the given algorithm. Function supports only RSA, EC
     * and EdDSA
     * and will return OID sha256WithRSAEncryption (1.2.840.113549.1.1.11) for
     * RSA,
     * ecdsa_with_SHA256 (1.2.840.10045.4.3.2) for EC, id-Ed25519 (1.3.101.112)
     * for Ed25519 and id-Ed448 (1.3.101.1123) for Ed448
     *
     * @param algorithm
     *            algorithm ("RSA", "EC", "Ed25519", "Ed448") to get OID for
     *
     * @return OID of the algorithm
     */
    public static AlgorithmIdentifier getAlgOID(final String algorithm) {
        if ("RSA".equalsIgnoreCase(algorithm)) {
            return new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.sha256WithRSAEncryption);
        }
        if (algorithm.startsWith("EC")) {
            return new AlgorithmIdentifier(
                    X9ObjectIdentifiers.ecdsa_with_SHA256);
        }
        if ("Ed448".equalsIgnoreCase(algorithm)) {
            return new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
        }
        if ("Ed25519".equalsIgnoreCase(algorithm)) {
            return new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
        }
        return null;
    }

    /**
     *
     * @param id
     *            name of KEK algorithm
     * @return KEK OID
     */
    public static ASN1ObjectIdentifier getKekOID(final String id) {
        return KEK_OIDS.get(id);
    }

    /**
     *
     * @param id
     *            name of key agreement algorithm
     * @return key agreement OID
     */
    public static final ASN1ObjectIdentifier getKeyAgreementOID(
            final String id) {
        return KEY_AGREEMENT_OIDS.get(id);
    }

    /**
     *
     * @param id
     *            name of key encryption algorithm
     * @return key encryption OID
     */
    public static ASN1ObjectIdentifier getKeyEncryptionOID(final String id) {
        return KEY_ENCRYPTION_OIDS.get(id);
    }

    public static Mac getMac(final String macId)
            throws NoSuchAlgorithmException {
        return Mac.getInstance(macId, CertUtility.BOUNCY_CASTLE_PROVIDER);
    }

    public static MessageDigest getMessageDigest(final String id)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(id.toUpperCase(),
                CertUtility.BOUNCY_CASTLE_PROVIDER);
    }

    public static ASN1ObjectIdentifier getOidForMac(final String macAlg) {
        final ASN1ObjectIdentifier ret = MAC_ALG_OIDS.getCmpAlgorithm(macAlg);
        if (ret != null) {
            return ret;
        }
        return new ASN1ObjectIdentifier(macAlg);
    }

    public static PasswordRecipient.PRF getPrf(final String id) {
        return PBKDF2_ALG_NAMES.getCmpAlgorithm(id);
    }

    /**
     * create a SecretKeyFactory related to the given id
     *
     * @param id
     *            PRF id
     * @return a related SecretKeyFactory
     * @throws NoSuchAlgorithmException
     *             if no SecretKeyFactory related to the id could be created
     */
    public static SecretKeyFactory getSecretKeyFactory(final String id)
            throws NoSuchAlgorithmException {
        return HELPER
                .createSecretKeyFactory(PBKDF2_ALG_NAMES.getJavaAlgorithm(id));
    }

    public static AlgorithmIdentifier getSigningAlgIdFromKey(final Key key) {
        return getSigningAlgIdFromKeyAlg(key.getAlgorithm());

    }

    public static AlgorithmIdentifier getSigningAlgIdFromKeyAlg(
            final String keyAlgorithm) {
        return DEFAULT_SIGNATURE_ALGORITHM_IDENTIFIER_FINDER
                .find(getSigningAlgNameFromKeyAlg(keyAlgorithm));
    }

    public static AlgorithmIdentifier getSigningAlgIdFromName(
            final String signatureAlgorithmName) {
        return DEFAULT_SIGNATURE_ALGORITHM_IDENTIFIER_FINDER
                .find(signatureAlgorithmName);
    }

    /**
     * get a feasible signing algorithm for the given key
     *
     * @param key
     *            the key to fetch the algorithm from
     * @return standard java name for signature algorithm or <code>null</code>
     *         if key uses algorithms beside RSA, EC or EdDSA
     */
    public static String getSigningAlgNameFromKey(final Key key) {
        return getSigningAlgNameFromKeyAlg(key.getAlgorithm());
    }

    /**
     * get a feasible signing algorithm for the given keyAlgorithm
     *
     * @param keyAlgorithm
     *            the algorithm to calculate the name from
     * @return standard java name for signature algorithm or <code>null</code>
     *         if key uses algorithms beside RSA, EC or EdDSA
     */
    public static String getSigningAlgNameFromKeyAlg(
            final String keyAlgorithm) {
        if (keyAlgorithm.startsWith("Ed")) {
            // EdDSA key
            return keyAlgorithm;
        }
        if ("EC".equals(keyAlgorithm)) {
            // EC key
            return "SHA256withECDSA";
        }
        return "SHA256with" + keyAlgorithm;
    }

    private static String normalizeId(final String id) {
        if (id == null) {
            LOGGER.error("id is null");
            return null;
        }
        return id.toLowerCase().replaceAll("[\\s-_]+", "");
    }

    // utility class
    private AlgorithmHelper() {

    }

}
