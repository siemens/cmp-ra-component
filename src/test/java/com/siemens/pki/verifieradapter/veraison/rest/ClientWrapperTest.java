package com.siemens.pki.verifieradapter.veraison.rest;
import org.junit.Test;
import org.junit.Assert;

public class ClientWrapperTest {

    /**
     * Given an attestation response,
     * When the data is not a valid JSON structure,
     * Then the attestation result must be considered negative.
     */
    @Test
    public void testIsAttestationResultPositive_withInvalidJwt() {
        ClientWrapper clientWrapper = new ClientWrapper("http://localhost");
        String input = "this is a test\ntest two";
        boolean result = false;
        try {
            result = clientWrapper.isAttestationResultPositive(input);
        } catch (Exception e) {
            Assert.fail("Exception thrown for invalid input that should have been handled: " + e.getMessage());
        }
        Assert.assertFalse(result);
    }

    /**
     * Given an attestation response,
     * When the data is valid JSON structure that contains a valid attestation result with an "affirming" status
     * Then the attestation result must be considered positive.
     */
    @Test
    public void testIsAttestationResultPositive_withValidJson() {
        ClientWrapper clientWrapper = new ClientWrapper("http://localhost");
        String input = "{\n  \"status\": \"complete\",\n  \"nonce\": \"uOwUWFRFSy9tv7dr7nhd20R9wu95Y1cdCoKU1mhLbXs=\",\n  \"expiry\": \"2025-07-10T07:33:20.239245584Z\",\n  \"accept\": [\n    \"application/vnd.parallaxsecond.key-attestation.tpm\",\n    \"application/eat+cwt; eat_profile=\\\"tag:psacertified.org,2023:psa#tfm\\\"\",\n    \"application/vnd.parallaxsecond.key-attestation.cca\",\n    \"application/pem-certificate-chain\",\n    \"application/eat-cwt; profile=\\\"http://arm.com/psa/2.0.0\\\"\",\n    \"application/eat+cwt; eat_profile=\\\"tag:psacertified.org,2019:psa#legacy\\\"\",\n    \"application/vnd.enacttrust.tpm-evidence\",\n    \"application/psa-attestation-token\",\n    \"application/eat-collection; profile=\\\"http://arm.com/CCA-SSD/1.0.0\\\"\",\n    \"application/atg-plugin-evidence\"\n  ],\n  \"evidence\": {\n    \"type\": \"application/atg-plugin-evidence\",\n    \"value\": \"eyJjbGFpbXNfc291cmNlcyI6W1siODBjMjRlZmEtNjcwMi00NTY3LTgxZjEtZmM2Yjk4ODU1N2QwIiwiMC41LjAiXV0sInBjcl9saXN0IjpbeyJkaWdlc3QiOiJ4X3p5WFdPVXJOSG96RlF3aVI4Y2p5c3pOZnc3QWJmV29EYVZmOEVhQmRzPSIsImRpZ2VzdF9hbGciOiJzaGEyNTYiLCJpbmRleCI6N31dLCJzaWduZXJfa2V5X2luZm9zIjp7ImtpZCI6IkFUY1dhMG1RNDhaY1hIQmY4ZkhLRitITkFmdThjRytLY0VBckthb1o4V3dlIn0sInRwbTJfcXVvdGUiOiJfMVJEUjRBWUFDSUFDOVV6aHdyOGRWVVQ4RlJrVXZreGVZeV9fTzN1YXRmV3JSSXZodTdxNVVKeUFDQzQ3QlJZVkVWTEwyMl90MnZ1ZUYzYlJIM0M3M2xqVngwS2dwVFdhRXR0ZXdBQUFBQUFSTDFsQUFBQUpBQUFBQUFCSUJrUUl3QVdOallBQUFBQkFBc0RnQUFBQUNBN0UydlhKcF8xbkxlSUVPdjZEdHlyOEdSNG5oUjVsTy1YU2JCXzl6Y0NvZz09IiwidHBtMl9xdW90ZV9hbGciOiJFQ0RTQSIsInRwbTJfcXVvdGVfc2lnIjoiQUJnQUN3QWdFQ2stRHh4eUNtQjdUMVFXMWMyaGkwTDQ3Skd2R0IwUkNmVGRSRGZWR0kwQUlER0ZCY183LVpaak5vNWtvX0Q1VEtfUlFINVNqejF6YjZkYUNMVXRPd01qIn0=\"\n  },\n  \"result\": \"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJOL0EiLCJkZXZlbG9wZXIiOiJWZXJhaXNvbiBQcm9qZWN0In0sImVhdF9ub25jZSI6InVPd1VXRlJGU3k5dHY3ZHI3bmhkMjBSOXd1OTVZMWNkQ29LVTFtaExiWHM9IiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbSwyMDIzOnZlcmFpc29uL2VhciIsImlhdCI6MTc1MjEzMjY1MCwic3VibW9kcyI6eyJBVEdfUExVR0lOIjp7ImVhci5hcHByYWlzYWwtcG9saWN5LWlkIjoicG9saWN5OkFUR19QTFVHSU4iLCJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWFyLnRydXN0d29ydGhpbmVzcy12ZWN0b3IiOnsiY29uZmlndXJhdGlvbiI6MCwiZXhlY3V0YWJsZXMiOjAsImZpbGUtc3lzdGVtIjowLCJoYXJkd2FyZSI6MCwiaW5zdGFuY2UtaWRlbnRpdHkiOjAsInJ1bnRpbWUtb3BhcXVlIjowLCJzb3VyY2VkLWRhdGEiOjAsInN0b3JhZ2Utb3BhcXVlIjowfX19fQ.sR6NzeeAeKdd_xe2iQF9uOLjXmQO7w20zXLVPKAjOLq1OTIRR8BWuGL5GcRCTonPbZIbyhdXJ4qMK4LnWEbCMw\"\n}\n";
        boolean result = false;
        try {
            result = clientWrapper.isAttestationResultPositive(input);
        } catch (Exception e) {
            Assert.fail("Exception thrown for valid input: " + e.getMessage());
        }
        Assert.assertTrue(result);
    }
}
