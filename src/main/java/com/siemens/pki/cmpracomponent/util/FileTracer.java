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

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;
import java.util.Base64.Encoder;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * message logger utility.
 *
 * If the system property "dumpdir" points to a writable directory, every
 * message at upstream and downstream is logged 3 times (as binary,as PEM, as
 * ASN.1 text trace). Each transaction goes to a separate sub directory
 * directory below "dumpdir".
 *
 */
public class FileTracer {

    private static final Encoder B64_ENCODER_WITHOUT_PADDING =
            Base64.getUrlEncoder().withoutPadding();

    private static final Logger LOGGER =
            LoggerFactory.getLogger(FileTracer.class);

    private static File msgDumpDirectory;

    static {
        final String dumpDirName = System.getProperty("dumpdir");
        if (dumpDirName != null) {
            msgDumpDirectory = new File(dumpDirName);
            if (!msgDumpDirectory.isDirectory()
                    || !msgDumpDirectory.canWrite()) {
                LOGGER.error(
                        msgDumpDirectory + " is not writable, disable dump");
                msgDumpDirectory = null;
            } else {
                LOGGER.info("dump transactions below " + msgDumpDirectory);
            }
        }
    }

    public static void logMessage(final PKIMessage msg,
            final String interfaceName) {
        if (msgDumpDirectory == null || msg == null) {
            return;
        }
        final String subDirName = "trans_" + B64_ENCODER_WITHOUT_PADDING
                .encodeToString(msg.getHeader().getTransactionID().getOctets());
        final File subDir = new File(msgDumpDirectory, subDirName);
        if (!subDir.isDirectory()) {
            subDir.mkdirs();
        }
        final String fileprefix =
                interfaceName + "_" + MessageDumper.msgTypeAsString(msg);
        try (final FileOutputStream binOut =
                new FileOutputStream(new File(subDir, fileprefix + ".PKI"));
                final FileWriter txtOut =
                        new FileWriter(new File(subDir, fileprefix + ".txt"));
                final PemWriter pemOut = new PemWriter(new FileWriter(
                        new File(subDir, fileprefix + ".pem")))) {
            final byte[] encodedMessage = msg.getEncoded(ASN1Encoding.DER);
            binOut.write(encodedMessage);
            pemOut.writeObject(new PemObject("PKIXCMP", encodedMessage));
            txtOut.write(ASN1Dump.dumpAsString(msg, true));
            txtOut.write(MessageDumper.dumpPkiMessage(msg));
        } catch (final IOException e) {
            LOGGER.error("error writing dump", e);
        }
    }

    // utility class
    private FileTracer() {

    }

}
