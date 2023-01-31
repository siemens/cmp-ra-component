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
package com.siemens.pki.cmpracomponent.msgvalidation;

import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * base of all CMP exceptions
 */
public class BaseCmpException extends Exception {

    private static final Logger LOGGER = LoggerFactory.getLogger(BaseCmpException.class);

    private static final long serialVersionUID = 1;
    protected final int failInfo;
    protected final String errorDetails;

    protected BaseCmpException(final String interfaceName, final Exception ex) {
        super("exception at " + interfaceName, ex);

        if (ex instanceof BaseCmpException) {
            this.failInfo = ((BaseCmpException) ex).failInfo;
            this.errorDetails = ((BaseCmpException) ex).errorDetails;
            LOGGER.warn("exception at " + interfaceName + ": " + errorDetails, ex);
        } else {
            this.failInfo = PKIFailureInfo.systemFailure;
            this.errorDetails = interfaceName + ": " + ex.getLocalizedMessage();
            LOGGER.warn("exception at " + interfaceName, ex);
        }
    }

    /**
     * @param interfaceName interface name used as prefix message text
     * @param failInfo      CMP failInfo proposed for CMP error message
     * @param errorDetails  description of some details related to the error
     * @param ex            the underlying exception
     */
    protected BaseCmpException(
            final String interfaceName, final int failInfo, final String errorDetails, final Throwable ex) {
        super(
                ex == null || ex.getMessage() == null ? errorDetails : ex.getMessage(),
                ex == null || ex.getCause() == null ? ex : ex.getCause());
        if (ex instanceof BaseCmpException) {
            this.failInfo = ((BaseCmpException) ex).failInfo;
            this.errorDetails = ((BaseCmpException) ex).errorDetails;
            LOGGER.warn("exception at " + interfaceName + ": " + errorDetails, ex);
        } else {
            this.failInfo = failInfo;
            this.errorDetails = interfaceName + ": " + errorDetails;
            if (ex != null) {
                LOGGER.warn("exception at " + interfaceName, ex);
            } else {
                LOGGER.warn("error at " + interfaceName + ": " + errorDetails);
            }
        }
    }

    public PKIBody asErrorBody() {
        return PkiMessageGenerator.generateErrorBody(failInfo, errorDetails);
    }

    @Override
    public String toString() {
        return "CmpException [failInfo=" + failInfo + ", errorDetails=" + errorDetails + "]";
    }
}
