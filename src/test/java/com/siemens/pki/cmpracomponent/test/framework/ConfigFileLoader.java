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
package com.siemens.pki.cmpracomponent.test.framework;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/** load configuration files in different runtime environments */
public class ConfigFileLoader {

    private static File fileBase = null;

    // utility class
    private ConfigFileLoader() {}

    public static InputStream getConfigFileAsStream(final String nameOfConfigFile) throws IOException {
        final File configFile = new File(nameOfConfigFile);
        if (configFile.isAbsolute()) {
            return new FileInputStream(configFile);
        }
        return new FileInputStream(new File(fileBase, nameOfConfigFile));
    }

    public static void setConfigFileBase(final File fileBase) {
        ConfigFileLoader.fileBase = fileBase;
    }
}
