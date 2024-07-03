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
package com.siemens.pki.cmpracomponent.util;

import static com.siemens.pki.cmpracomponent.util.NullUtil.defaultIfNull;
import static com.siemens.pki.cmpracomponent.util.NullUtil.ifNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * message logger utility.
 * <p>
 * If the system property "dumpdir" points to a writable directory, every
 * message at upstream and downstream is logged 3 times (as binary,as PEM, as
 * ASN.1 text trace). Each transaction goes to a separate sub directory
 * directory below "dumpdir".
 */
public class FileTracer {

    private static final Encoder B64_ENCODER_WITHOUT_PADDING =
            Base64.getUrlEncoder().withoutPadding();

    private static final Logger LOGGER = LoggerFactory.getLogger(FileTracer.class);

    private static File msgDumpDirectory;

    private static boolean enablePemDump;

    private static boolean enableTxtDump;

    private static boolean enableDerDump;

    private static boolean enableAsn1Dump;

    private static boolean enableJsonDump;

    private static boolean enableYamlDump;

    static {
        final String dumpDirName = System.getProperty("dumpdir");
        // "pem+txt+der+asn1+json+yaml"
        final String dumpFormat = System.getProperty("dumpformat", "yaml").toLowerCase();
        init(dumpDirName, dumpFormat);
    }

    /**
     * (re-)intialize the {@link FileTracer}
     * @param dumpDirName directory to dump to
     * @param dumpFormat  dump format to use, one or more of
     *                    "pem,txt,der,asn1,json,yaml" concatinated in one string
     */
    public static void init(final String dumpDirName, final String dumpFormat) {
        enablePemDump = dumpFormat.contains("pem");
        enableTxtDump = dumpFormat.contains("txt");
        enableDerDump = dumpFormat.contains("der");
        enableAsn1Dump = dumpFormat.contains("asn");
        enableJsonDump = dumpFormat.contains("json");
        enableYamlDump = dumpFormat.contains("yaml");

        if (dumpDirName == null) {
            msgDumpDirectory = null;
            return;
        }
        msgDumpDirectory = new File(dumpDirName);
        if (!msgDumpDirectory.isDirectory() || !msgDumpDirectory.canWrite()) {
            LOGGER.error(msgDumpDirectory + " is not writable, disable dump");
            msgDumpDirectory = null;
        } else {
            LOGGER.info("dump transactions below " + msgDumpDirectory);
        }
    }

    private static final AtomicLong messagecounter = new AtomicLong(0);

    /**
     * dump a message to the dumpdir
     *
     * @param msg           message to dump
     * @param interfaceName file name prefix to use
     * @return directory where the log goes in
     */
    public static File logMessage(final PKIMessage msg, final String interfaceName) {
        if (!dumpEnabled(msg)) {
            return null;
        }
        try {
            final File subDir = getCreateTransactionDirectory(msg);
            final String fileprefix = String.format(
                    "%03d_%s_%s", messagecounter.incrementAndGet(), interfaceName, MessageDumper.msgTypeAsString(msg));
            if (isPemOrDerOutEnabled()) {
                final byte[] encodedMessage = msg.getEncoded(ASN1Encoding.DER);
                if (enableDerDump) {
                    try (final FileOutputStream binOut = new FileOutputStream(new File(subDir, fileprefix + ".PKI"))) {
                        binOut.write(encodedMessage);
                    }
                }
                if (enablePemDump) {
                    try (final PemWriter pemOut =
                            new PemWriter(new FileWriter(new File(subDir, fileprefix + ".pem")))) {
                        pemOut.writeObject(new PemObject("PKIXCMP", encodedMessage));
                    }
                }
            }
            if (isTxtOutEnabled()) {
                try (final FileWriter txtOut = new FileWriter(new File(subDir, fileprefix + ".txt"))) {
                    if (enableTxtDump) {
                        txtOut.write(MessageDumper.dumpPkiMessage(msg));
                    }
                    if (enableAsn1Dump) {
                        txtOut.write(ASN1Dump.dumpAsString(msg, true));
                    }
                }
            }
            if (enableJsonDump) {
                try (final FileWriter txtOut = new FileWriter(new File(subDir, fileprefix + ".json"))) {
                    txtOut.write(JsonYamlMessageDumper.dumpPkiMessageAsJson(msg));
                }
            }
            if (enableYamlDump) {
                try (final FileWriter txtOut = new FileWriter(new File(subDir, fileprefix + ".yaml"))) {
                    txtOut.write(JsonYamlMessageDumper.dumpPkiMessageAsYaml(msg));
                }
            }
            return subDir;
        } catch (final Exception e) {
            LOGGER.error("error writing dump", e);
            return null;
        }
    }

    private static boolean dumpEnabled(final PKIMessage msg) {
        if (msgDumpDirectory == null || msg == null) {
            return false;
        }
        return isPemOrDerOutEnabled() || isTxtOutEnabled() || enableJsonDump || enableYamlDump;
    }

    private static File getCreateTransactionDirectory(final PKIMessage msg) {
        final String transactionId = ifNotNull(
                msg.getHeader().getTransactionID(), tid -> B64_ENCODER_WITHOUT_PADDING.encodeToString(tid.getOctets()));
        final String tidAsString = defaultIfNull(transactionId, "null");
        final String subDirName = "trans_" + tidAsString;
        final File subDir = new File(msgDumpDirectory, subDirName);
        if (!subDir.isDirectory()) {
            subDir.mkdirs();
        }
        return subDir;
    }

    private static boolean isTxtOutEnabled() {
        return enableAsn1Dump || enableTxtDump;
    }

    private static boolean isPemOrDerOutEnabled() {
        return enableDerDump || enablePemDump;
    }

    // utility class
    private FileTracer() {}
}
