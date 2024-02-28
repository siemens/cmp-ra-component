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

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.util.ConfigLogger;
import com.siemens.pki.cmpracomponent.util.MessageDumper;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Objects;
import java.util.function.BiPredicate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContent;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

/**
 * A CMP message validator to ensure CMP messages conform to RFC 4210.
 */
public class MessageBodyValidator implements ValidatorIF<String> {
    private static final String CERT_REQ_ID_MUST_BE_0 = "CertReqId must be 0";

    /**
     *
     */
    private static final ASN1Integer ASN1INTEGER_0 = new ASN1Integer(0);

    private static final BigInteger MINUS_ONE = BigInteger.ONE.negate();

    private static final JcaX509ContentVerifierProviderBuilder jcaX509ContentVerifierProviderBuilder =
            new JcaX509ContentVerifierProviderBuilder().setProvider(CertUtility.getBouncyCastleProvider());

    private final String interfaceName;

    private final BiPredicate<String, Integer> isRaVerifiedAcceptable;

    private final CmpMessageInterface cmpInterfaceConfig;

    private final String certProfile;

    /**
     * ctor
     * @param interfaceName          name used in error messages and logging
     * @param isRaVerifiedAcceptable should RaVerified accepted in POPO?
     * @param cmpInterfaceConfig     specific interface (downstream/upstream)
     *                               configuration
     * @param certProfile            certificate profile of this transaction
     */
    public MessageBodyValidator(
            final String interfaceName,
            final BiPredicate<String, Integer> isRaVerifiedAcceptable,
            final CmpMessageInterface cmpInterfaceConfig,
            final String certProfile) {
        this.interfaceName = interfaceName;
        this.isRaVerifiedAcceptable = isRaVerifiedAcceptable;
        this.certProfile = certProfile;
        this.cmpInterfaceConfig = cmpInterfaceConfig;
    }

    private void assertEnrollmentEqual(
            final int enrollmentType, final Object value1, final Object value2, final String errorMsg)
            throws CmpEnrollmentException {
        if (!Objects.equals(value1, value2)) {
            throw new CmpEnrollmentException(enrollmentType, interfaceName, PKIFailureInfo.badDataFormat, errorMsg);
        }
    }

    private void assertEnrollmentValueIsNull(
            final int enrollmentType, final Object value, final int failInfo, final String errorMsg)
            throws CmpEnrollmentException {
        if (!Objects.isNull(value)) {
            throw new CmpEnrollmentException(enrollmentType, interfaceName, failInfo, errorMsg);
        }
    }

    private void assertEnrollmentValueNotNull(
            final int enrollmentType, final Object value, final int failInfo, final String fieldName)
            throws CmpEnrollmentException {
        if (Objects.isNull(value)) {
            throw new CmpEnrollmentException(enrollmentType, interfaceName, failInfo, "missing '" + fieldName + "'");
        }
    }

    private void assertEqual(final Object value1, final Object value2, final String errorMsg)
            throws CmpValidationException {
        if (!Objects.equals(value1, value2)) {
            throw new CmpValidationException(interfaceName, PKIFailureInfo.badDataFormat, errorMsg);
        }
    }

    private void assertExactlyOneElementInArray(final Object[] array, final String fieldName)
            throws CmpValidationException {
        if (array == null) {
            throw new CmpValidationException(
                    interfaceName, PKIFailureInfo.addInfoNotAvailable, "missing '" + fieldName + "'");
        }
        if (array.length != 1) {
            throw new CmpValidationException(
                    interfaceName, PKIFailureInfo.badDataFormat, "'" + fieldName + "' must have one element");
        }
        if (array[0] == null) {
            throw new CmpValidationException(
                    interfaceName, PKIFailureInfo.addInfoNotAvailable, "missing '" + fieldName + "'");
        }
    }

    private void assertValueIsNull(final Object value, final int failInfo, final String errorMsg)
            throws CmpValidationException {
        if (!Objects.isNull(value)) {
            throw new CmpValidationException(interfaceName, failInfo, errorMsg);
        }
    }

    private void assertValueNotNull(final Object value, final int failInfo, final String fieldName)
            throws CmpValidationException {
        if (Objects.isNull(value)) {
            throw new CmpValidationException(interfaceName, failInfo, "missing '" + fieldName + "'");
        }
    }

    /**
     * Validates the given <code>message</code> to ensure that it conforms to the
     * CMP profile.
     *
     * @param message the CMP message to validate
     * @throws BaseCmpException if validation failed
     */
    @Override
    public String validate(final PKIMessage message) throws BaseCmpException {
        try {
            final ASN1GeneralizedTime messageTime = message.getHeader().getMessageTime();
            if (messageTime != null) {
                final long diffInMillis = messageTime.getDate().getTime() - new Date().getTime();
                if (!ConfigLogger.log(
                        interfaceName,
                        "CmpMessageInterface.isMessageTimeDeviationAllowed(long)",
                        () -> cmpInterfaceConfig.isMessageTimeDeviationAllowed(diffInMillis / 1000L))) {
                    throw new CmpValidationException(
                            interfaceName, PKIFailureInfo.badTime, "message time out of allowed range");
                }
            }

            final PKIBody body = message.getBody();
            final ASN1Encodable content = body.getContent();
            final int bodyType = body.getType();
            switch (bodyType) {
                case PKIBody.TYPE_INIT_REQ:
                case PKIBody.TYPE_CERT_REQ:
                case PKIBody.TYPE_KEY_UPDATE_REQ:
                    validateCrmfCertReq(bodyType, (CertReqMessages) content, certProfile, bodyType);
                    break;
                case PKIBody.TYPE_P10_CERT_REQ:
                    validateP10CertReq((CertificationRequest) content);
                    break;
                case PKIBody.TYPE_CERT_REP:
                case PKIBody.TYPE_INIT_REP:
                case PKIBody.TYPE_KEY_UPDATE_REP:
                    validateCertRep((CertRepMessage) content);
                    break;
                case PKIBody.TYPE_REVOCATION_REQ:
                    validateRevReq((RevReqContent) content);
                    break;
                case PKIBody.TYPE_REVOCATION_REP:
                    validateRevRep((RevRepContent) content);
                    break;
                case PKIBody.TYPE_CERT_CONFIRM:
                    validateCertConfirm((CertConfirmContent) content);
                    break;
                case PKIBody.TYPE_CONFIRM:
                    validateConfirm((PKIConfirmContent) content);
                    break;
                case PKIBody.TYPE_POLL_REQ:
                    validatePollReq((PollReqContent) content);
                    break;
                case PKIBody.TYPE_POLL_REP:
                    validatePollRep((PollRepContent) content);
                    break;
                case PKIBody.TYPE_GEN_MSG:
                    validateGenMsg((GenMsgContent) content);
                    break;
                case PKIBody.TYPE_GEN_REP:
                    validateGenRep((GenRepContent) content);
                    break;
                case PKIBody.TYPE_ERROR:
                    validateErrorMsg((ErrorMsgContent) content);
                    break;
                case PKIBody.TYPE_NESTED:
                    break;
                default:
                    throw new CmpValidationException(
                            interfaceName,
                            PKIFailureInfo.badDataFormat,
                            MessageDumper.msgTypeAsString(message.getBody()) + " not supported");
            }
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Throwable thr) {
            throw new CmpValidationException(
                    interfaceName,
                    PKIFailureInfo.systemFailure,
                    "internal error in message validation: " + thr.getLocalizedMessage());
        }
        return certProfile;
    }

    private void validateCertConfirm(final CertConfirmContent content) throws BaseCmpException {
        final CertStatus[] certStatusArray = content.toCertStatusArray();
        assertExactlyOneElementInArray(certStatusArray, "certStatus");
        final CertStatus certStatus = certStatusArray[0];
        assertValueNotNull(certStatus.getCertHash(), PKIFailureInfo.badDataFormat, "CertHash");
        assertEqual(certStatus.getCertReqId(), ASN1INTEGER_0, CERT_REQ_ID_MUST_BE_0);
    }

    private void validateCertRep(final CertRepMessage content) throws BaseCmpException {
        final CertResponse[] responses = content.getResponse();
        assertExactlyOneElementInArray(responses, "CertResponse");
        final CertResponse response = responses[0];
        assertEqual(response.getCertReqId(), ASN1INTEGER_0, CERT_REQ_ID_MUST_BE_0);
        final CertifiedKeyPair certifiedKeyPair = response.getCertifiedKeyPair();
        if (certifiedKeyPair != null) {
            validatePositivePkiStatusInfo(response.getStatus());
            final CertOrEncCert certOrEncCert = certifiedKeyPair.getCertOrEncCert();
            assertValueNotNull(certOrEncCert, PKIFailureInfo.badDataFormat, "CertOrEncCert");
            assertValueNotNull(certOrEncCert.getCertificate(), PKIFailureInfo.badDataFormat, "Certificate");
        } else {
            validateNegativePkiStatusInfo(response.getStatus());
        }
    }

    private void validateConfirm(final PKIConfirmContent content) {
        // always ASN1Null
    }

    private void validateCrmfCertReq(
            final int enrollmentType, final CertReqMessages content, final String certProfile, final int bodyType)
            throws CmpValidationException {
        final CertReqMsg[] certReqMsgs = content.toCertReqMsgArray();
        assertExactlyOneElementInArray(certReqMsgs, "CertReqMsg");
        final CertReqMsg certReqMsg = certReqMsgs[0];
        final CertRequest certReq = certReqMsg.getCertReq();
        assertEnrollmentEqual(enrollmentType, certReq.getCertReqId(), ASN1INTEGER_0, CERT_REQ_ID_MUST_BE_0);
        final CertTemplate certTemplate = certReq.getCertTemplate();
        final int versionInTemplate = certTemplate.getVersion();
        if (versionInTemplate != -1 && versionInTemplate != 2) {
            throw new CmpEnrollmentException(
                    enrollmentType, interfaceName, PKIFailureInfo.badCertTemplate, "certTemplate version must be 2");
        }
        assertEnrollmentValueNotNull(
                enrollmentType, certTemplate.getSubject(), PKIFailureInfo.badCertTemplate, "subject in template");
        final ProofOfPossession popo = certReqMsg.getPop();
        final SubjectPublicKeyInfo publicKeyInfo = certTemplate.getPublicKey();
        if (popo == null) {
            try {
                if (publicKeyInfo.getPublicKeyData().getBytes().length > 0) {
                    throw new CmpEnrollmentException(
                            enrollmentType,
                            interfaceName,
                            PKIFailureInfo.badPOP,
                            "public key present in template but POPO missing");
                }
            } catch (final NullPointerException ex) {
                // public key absent
            }
        } else {
            switch (popo.getType()) {
                case ProofOfPossession.TYPE_RA_VERIFIED:
                    if (!ConfigLogger.log(
                            interfaceName,
                            "Configuration.isRaVerifiedAcceptable",
                            isRaVerifiedAcceptable::test,
                            certProfile,
                            bodyType)) {
                        throw new CmpEnrollmentException(
                                enrollmentType, interfaceName, PKIFailureInfo.badPOP, "POPO RaVerified not allowed");
                    }
                    break;
                case ProofOfPossession.TYPE_SIGNING_KEY:
                    try {
                        assertEnrollmentValueNotNull(
                                enrollmentType, publicKeyInfo, PKIFailureInfo.badPOP, "publicKey in template");
                        final POPOSigningKey popoSigningKey = (POPOSigningKey) popo.getObject();
                        assertEnrollmentValueIsNull(
                                enrollmentType,
                                popoSigningKey.getPoposkInput(),
                                PKIFailureInfo.badPOP,
                                "PoposkInput must be absent");
                        final PublicKey publicKey = KeyFactory.getInstance(
                                        publicKeyInfo
                                                .getAlgorithm()
                                                .getAlgorithm()
                                                .toString(),
                                        CertUtility.getBouncyCastleProvider())
                                .generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded(ASN1Encoding.DER)));
                        final Signature sig = Signature.getInstance(
                                popoSigningKey
                                        .getAlgorithmIdentifier()
                                        .getAlgorithm()
                                        .getId(),
                                CertUtility.getBouncyCastleProvider());
                        sig.initVerify(publicKey);
                        sig.update(certReq.getEncoded(ASN1Encoding.DER));
                        if (!sig.verify(popoSigningKey.getSignature().getBytes())) {
                            throw new CmpEnrollmentException(
                                    enrollmentType, interfaceName, PKIFailureInfo.badPOP, "POPO broken");
                        }
                    } catch (final IOException
                            | NoSuchAlgorithmException
                            | InvalidKeyException
                            | InvalidKeySpecException
                            | SignatureException ex) {
                        throw new CmpEnrollmentException(
                                enrollmentType,
                                interfaceName,
                                PKIFailureInfo.badPOP,
                                "exception while calculating POPO: " + ex.getLocalizedMessage());
                    }
                    break;
                default:
                    throw new CmpEnrollmentException(
                            enrollmentType, interfaceName, PKIFailureInfo.badPOP, "unsupported POPO type");
            }
        }
    }

    private void validateErrorMsg(final ErrorMsgContent content) throws CmpValidationException {
        final PKIStatusInfo pkiStatusInfo = content.getPKIStatusInfo();
        validateNegativePkiStatusInfo(pkiStatusInfo);
    }

    private void validateGenMsg(final GenMsgContent content) throws BaseCmpException {

        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertExactlyOneElementInArray(itav, "InfoTypeAndValue");
        assertValueNotNull(itav[0].getInfoType(), PKIFailureInfo.badDataFormat, "InfoType");
    }

    private void validateGenRep(final GenRepContent content) throws BaseCmpException {

        final InfoTypeAndValue[] itav = content.toInfoTypeAndValueArray();
        assertExactlyOneElementInArray(itav, "InfoTypeAndValue");
        assertValueNotNull(itav[0].getInfoType(), PKIFailureInfo.badDataFormat, "InfoType");
    }

    private void validateNegativePkiStatusInfo(final PKIStatusInfo pkiStatusInfo) throws CmpValidationException {
        switch (pkiStatusInfo.getStatus().intValue()) {
            case PKIStatus.WAITING:
                assertValueIsNull(
                        pkiStatusInfo.getFailInfo(), PKIFailureInfo.badDataFormat, "\"waiting\" and failInfo is set");
                return;
            case PKIStatus.REJECTION:
                return;
            default:
                throw new CmpValidationException(
                        interfaceName,
                        PKIFailureInfo.badMessageCheck,
                        "status must have have the value \"rejection\" or \"waiting\"");
        }
    }

    private void validateP10CertReq(final CertificationRequest content) throws BaseCmpException {
        final PKCS10CertificationRequest p10Request = new PKCS10CertificationRequest(content);
        assertValueNotNull(p10Request.getSubject(), PKIFailureInfo.badCertTemplate, "Subject");
        try {
            if (!p10Request.isSignatureValid(
                    jcaX509ContentVerifierProviderBuilder.build(p10Request.getSubjectPublicKeyInfo()))) {
                throw new CmpValidationException(
                        interfaceName, PKIFailureInfo.badPOP, "PKCS#10 signature validation failed");
            }
        } catch (OperatorCreationException | PKCSException e) {
            throw new CmpValidationException(
                    interfaceName,
                    PKIFailureInfo.badPOP,
                    "PKCS#10 signature validation failed: " + e.getLocalizedMessage());
        }
    }

    private void validatePollRep(final PollRepContent content) throws BaseCmpException {
        assertEqual(content.size(), 1, "exactly one certReqId");
        final BigInteger reqId = content.getCertReqId(0).getValue();
        if (!MINUS_ONE.equals(reqId)) {
            assertEqual(reqId, BigInteger.ZERO, "certReqId must be 0 or -1");
        }
    }

    private void validatePollReq(final PollReqContent content) throws BaseCmpException {

        final BigInteger[] reqIds = content.getCertReqIdValues();
        assertExactlyOneElementInArray(reqIds, "CertReqIdValues");
        final BigInteger reqId = reqIds[0];
        if (!MINUS_ONE.equals(reqId)) {
            assertEqual(reqId, BigInteger.ZERO, "certReqId must be 0 or -1");
        }
    }

    private void validatePositivePkiStatusInfo(final PKIStatusInfo pkiStatusInfo) throws CmpValidationException {
        switch (pkiStatusInfo.getStatus().intValue()) {
            case PKIStatus.GRANTED:
            case PKIStatus.GRANTED_WITH_MODS:
                assertValueIsNull(
                        pkiStatusInfo.getFailInfo(),
                        PKIFailureInfo.badDataFormat,
                        "\"accepted\" or \"grantedWithMods\" but failInfo is set");
                return;
            default:
                assertEqual(
                        pkiStatusInfo.getStatus().intValue(),
                        PKIStatus.REJECTION,
                        "status must have have the value \"accepted\" or \"grantedWithMods\"");
        }
    }

    private void validateRevRep(final RevRepContent content) throws BaseCmpException {
        final PKIStatusInfo[] statuses = content.getStatus();
        assertExactlyOneElementInArray(statuses, "status");
        final PKIStatusInfo statusInfo = statuses[0];
        if (statusInfo.getStatus().intValue() == PKIStatus.GRANTED) {
            validatePositivePkiStatusInfo(statusInfo);
        } else {
            validateNegativePkiStatusInfo(statusInfo);
        }
    }

    private void validateRevReq(final RevReqContent content) throws BaseCmpException {

        final RevDetails[] revDetails = content.toRevDetailsArray();
        assertExactlyOneElementInArray(revDetails, "RevDetails");
        final CertTemplate certDetails = revDetails[0].getCertDetails();
        assertValueNotNull(certDetails, PKIFailureInfo.addInfoNotAvailable, "certDetails");
        assertValueNotNull(certDetails.getSerialNumber(), PKIFailureInfo.addInfoNotAvailable, "SerialNumber");
        assertValueNotNull(certDetails.getIssuer(), PKIFailureInfo.addInfoNotAvailable, "Issuer");
        final Extensions crlEntryDetails = revDetails[0].getCrlEntryDetails();
        assertValueNotNull(crlEntryDetails, PKIFailureInfo.addInfoNotAvailable, "CrlEntryDetails");
        final Extension reasonCodeExt = crlEntryDetails.getExtension(Extension.reasonCode);
        assertValueNotNull(reasonCodeExt, PKIFailureInfo.addInfoNotAvailable, "reasonCode");
        final long reasonCode = ASN1Enumerated.getInstance(reasonCodeExt.getParsedValue())
                .getValue()
                .longValue();
        if (reasonCode < 0 || reasonCode > 10) {
            throw new CmpValidationException(interfaceName, PKIFailureInfo.badDataFormat, "reasonCode out of range");
        }
    }
}
