/*
 *  Copyright (c) 2024 Siemens AG
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

import java.util.Arrays;
import java.util.Collection;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * helper class for configuration access logging
 */
public class ConfigLogger {

    private static final String DYNAMIC_CONFIGURATION_EXCEPTION = "DynamicConfigurationException: ";
    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigLogger.class);

    private static <T> void doInnerLogging(
            String interfaceName, String accessFunctionName, String certProfile, Integer bodyType, T ret) {
        if (LOGGER.isDebugEnabled()) {
            final String logMsg = "call {}({}, {}) for \"{}\" -> {}";
            if (ret instanceof byte[]) {
                LOGGER.debug(
                        logMsg,
                        accessFunctionName,
                        certProfile,
                        typeToString(bodyType),
                        interfaceName,
                        Hex.toHexString((byte[]) ret));
            } else if (ret instanceof Collection<?>) {
                LOGGER.debug(
                        logMsg,
                        accessFunctionName,
                        certProfile,
                        typeToString(bodyType),
                        interfaceName,
                        Arrays.toString(((Collection<?>) ret).toArray()));
            } else if (ret != null && ret.getClass().isArray()) {
                LOGGER.debug(
                        logMsg,
                        accessFunctionName,
                        certProfile,
                        typeToString(bodyType),
                        interfaceName,
                        Arrays.toString((Object[]) ret));
            } else {
                LOGGER.debug(logMsg, accessFunctionName, certProfile, typeToString(bodyType), interfaceName, ret);
            }
        }
    }

    private static <T> void doInnerLogging(String interfaceName, String accessFunctionName, T ret) {
        if (LOGGER.isDebugEnabled()) {
            final String logMsg = "call {} for \"{}\" -> {}";
            if (ret instanceof byte[]) {
                LOGGER.debug(logMsg, accessFunctionName, interfaceName, Hex.toHexString((byte[]) ret));
            } else if (ret instanceof Collection<?>) {
                LOGGER.debug(
                        logMsg, accessFunctionName, interfaceName, Arrays.toString(((Collection<?>) ret).toArray()));
            } else if (ret != null && ret.getClass().isArray()) {
                LOGGER.debug(logMsg, accessFunctionName, interfaceName, Arrays.toString((Object[]) ret));
            } else {
                LOGGER.debug(logMsg, accessFunctionName, interfaceName, ret);
            }
        }
    }

    /**
     * log access to mandatory configuration value
     *
     * @param <T>                return type of access function
     * @param interfaceName      related interface of configuration
     * @param accessFunctionName name of access function
     * @param accessFunction     the access function
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request/response PKI Message Body type
     * @return return value of access function
     * @throws NullPointerException if return value was <code>null</code>
     */
    public static <T> T log(
            String interfaceName,
            String accessFunctionName,
            BiFunction<String, Integer, T> accessFunction,
            String certProfile,
            Integer bodyType) {
        T ret;
        try {
            ret = accessFunction.apply(certProfile, bodyType);
        } catch (final Throwable ex) {
            final String errorMsg = "exception calling " + accessFunctionName + "(" + certProfile + ", "
                    + typeToString(bodyType) + ") for \"" + interfaceName + "\"";
            LOGGER.error(errorMsg, ex);
            Throwable cause = ex.getCause();
            while (cause != null) {
                LOGGER.error("cause", cause);
                cause = cause.getCause();
            }
            throw new RuntimeException(DYNAMIC_CONFIGURATION_EXCEPTION + errorMsg, ex);
        }
        doInnerLogging(interfaceName, accessFunctionName, certProfile, bodyType, ret);
        if (ret == null) {
            final String logMsg = "calling " + accessFunctionName + "(" + certProfile + ", " + typeToString(bodyType)
                    + ") for \"" + interfaceName + "\" returns null, but this configuration item is mandatory";
            LOGGER.error(logMsg);
            throw new RuntimeException(DYNAMIC_CONFIGURATION_EXCEPTION + logMsg);
        }
        return ret;
    }

    /**
     * log access to mandatory configuration value
     *
     * @param <T>                return type of access function
     * @param interfaceName      related interface of configuration
     * @param accessFunctionName name of access function
     * @param accessFunction     the access function
     * @return return value of access function
     * @throws NullPointerException if return value was <code>null</code>
     */
    public static <T> T log(String interfaceName, String accessFunctionName, Supplier<T> accessFunction) {
        T ret;
        try {
            ret = accessFunction.get();
        } catch (final Throwable ex) {
            final String errorMsg = "exception calling " + accessFunctionName + " for \"" + interfaceName + "\"";
            LOGGER.error(errorMsg, ex);
            Throwable cause = ex.getCause();
            while (cause != null) {
                LOGGER.error("cause", cause);
                cause = cause.getCause();
            }
            throw new RuntimeException(DYNAMIC_CONFIGURATION_EXCEPTION + errorMsg, ex);
        }
        doInnerLogging(interfaceName, accessFunctionName, ret);
        if (ret == null) {
            final String logMsg = "calling " + accessFunctionName + " for \"" + interfaceName
                    + "\" returns null, but this configuration item is mandatory";
            LOGGER.error(logMsg);
            throw new RuntimeException(DYNAMIC_CONFIGURATION_EXCEPTION + logMsg);
        }
        return ret;
    }

    /**
     * log access to optional configuration value
     *
     * @param <T>                return type of access function
     * @param interfaceName      related interface of configuration
     * @param accessFunctionName name of access function
     * @param accessFunction     the access function
     * @param certProfile certificate profile extracted from the CMP request header
     *                    generalInfo field or <code>null</code> if no certificate
     *                    profile was specified
     * @param bodyType    request/response PKI Message Body type
     * @return return value of access function
     * @throws NullPointerException if return value of access function was
     *                              <code>null</code>
     */
    public static <T> T logOptional(
            String interfaceName,
            String accessFunctionName,
            BiFunction<String, Integer, T> accessFunction,
            String certProfile,
            Integer bodyType) {
        T ret;
        try {
            ret = accessFunction.apply(certProfile, bodyType);
        } catch (final Throwable ex) {
            final String errorMsg = "exception calling " + accessFunctionName + "(" + certProfile + ", "
                    + typeToString(bodyType) + ") for \"" + interfaceName + "\"";
            LOGGER.error(errorMsg, ex);
            Throwable cause = ex.getCause();
            while (cause != null) {
                LOGGER.error("cause", cause);
                cause = cause.getCause();
            }
            throw new RuntimeException(DYNAMIC_CONFIGURATION_EXCEPTION + errorMsg, ex);
        }
        doInnerLogging(interfaceName, accessFunctionName, certProfile, bodyType, ret);
        return ret;
    }

    /**
     * log access to optional configuration value
     *
     * @param <T>                return type of access function
     * @param interfaceName      related interface of configuration
     * @param accessFunctionName name of access function
     * @param accessFunction     the access function
     * @return return value of access function
     * @throws NullPointerException if return value of access function was
     *                              <code>null</code>
     */
    public static <T> T logOptional(String interfaceName, String accessFunctionName, Supplier<T> accessFunction) {
        T ret;
        try {
            ret = accessFunction.get();
        } catch (final Throwable ex) {
            final String errorMsg = "exception while calling " + accessFunctionName + " for  \"" + interfaceName + "\"";
            LOGGER.error(errorMsg, ex);
            Throwable cause = ex.getCause();
            while (cause != null) {
                LOGGER.error("cause", cause);
                cause = cause.getCause();
            }
            throw new RuntimeException(DYNAMIC_CONFIGURATION_EXCEPTION + errorMsg, ex);
        }
        doInnerLogging(interfaceName, accessFunctionName, ret);
        return ret;
    }

    private static String typeToString(Integer bodyType) {
        if (bodyType == null) {
            return "<null>";
        }
        return MessageDumper.msgTypeAsString(bodyType) + "(" + bodyType + ")";
    }
    // utility class
    private ConfigLogger() {}
}
