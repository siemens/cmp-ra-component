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
package com.siemens.pki.cmpracomponent.test;

import static org.junit.Assert.assertTrue;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.test.framework.HeaderProviderForTest;
import com.siemens.pki.cmpracomponent.util.FileTracer;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/** test the {@link FileTracer} */
@RunWith(Parameterized.class)
public class TestFileTracer {

    @Parameters(name = "{index}: dumpDirName=>{0}, dumpFormat=>{1}")
    public static List<Object[]> data() throws IOException {
        String tempDir = Files.createTempDirectory("dumptest").toFile().getAbsolutePath();
        Object[][] ret = new Object[][] {
            {null, "asn", (Function<File, Boolean>) f -> f == null},
            {tempDir, "", (Function<File, Boolean>) f -> f == null},
            {tempDir, "pem,txt,der,asn1,json,yaml", (Function<File, Boolean>) f -> f.listFiles().length == 5},
            {
                tempDir,
                "pem",
                (Function<File, Boolean>)
                        f -> f.listFiles()[0].getAbsolutePath().endsWith(".pem")
            },
            {
                tempDir,
                "txt",
                (Function<File, Boolean>)
                        f -> f.listFiles()[0].getAbsolutePath().endsWith(".txt")
            },
            {
                tempDir,
                "der",
                (Function<File, Boolean>)
                        f -> f.listFiles()[0].getAbsolutePath().endsWith(".PKI")
            },
            {
                tempDir,
                "asn1",
                (Function<File, Boolean>)
                        f -> f.listFiles()[0].getAbsolutePath().endsWith(".txt")
            },
            {
                tempDir,
                "json",
                (Function<File, Boolean>)
                        f -> f.listFiles()[0].getAbsolutePath().endsWith(".json")
            },
            {
                tempDir,
                "yaml",
                (Function<File, Boolean>)
                        f -> f.listFiles()[0].getAbsolutePath().endsWith(".yaml")
            },
            {"unwritable", "pem,txt,der,asn1,json,yaml", (Function<File, Boolean>) f -> f == null},
        };
        return Arrays.asList(ret);
    }

    private final Function<File, Boolean> testValidator;
    private final String dumpFormat;
    private final String dumpDirName;

    public TestFileTracer(String dumpDirName, String dumpFormat, Function<File, Boolean> testValidator) {
        this.dumpDirName = dumpDirName;
        this.dumpFormat = dumpFormat;
        this.testValidator = testValidator;
        FileTracer.init(dumpDirName, dumpFormat);
    }

    @Test
    public void testDumper() throws Exception {
        PKIMessage testMessage = PkiMessageGenerator.generateUnprotectMessage(
                new HeaderProviderForTest("noProfile"), PkiMessageGenerator.generatePkiConfirmBody());
        assertTrue(
                dumpFormat + ":" + dumpDirName, testValidator.apply(FileTracer.logMessage(testMessage, "testdumper")));
    }
}
