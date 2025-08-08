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
        String input = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJOL0EiLCJkZXZlbG9wZXIiOiJWZXJhaXNvbiBQcm9qZWN0In0sImVhdF9ub25jZSI6InVPd1VXRlJGU3k5dHY3ZHI3bmhkMjBSOXd1OTVZMWNkQ29LVTFtaExiWHM9IiwiZWF0X3Byb2ZpbGUiOiJ0YWc6Z2l0aHViLmNvbSwyMDIzOnZlcmFpc29uL2VhciIsImlhdCI6MTc1MjEzMjY1MCwic3VibW9kcyI6eyJBVEdfUExVR0lOIjp7ImVhci5hcHByYWlzYWwtcG9saWN5LWlkIjoicG9saWN5OkFUR19QTFVHSU4iLCJlYXIuc3RhdHVzIjoiYWZmaXJtaW5nIiwiZWFyLnRydXN0d29ydGhpbmVzcy12ZWN0b3IiOnsiY29uZmlndXJhdGlvbiI6MCwiZXhlY3V0YWJsZXMiOjAsImZpbGUtc3lzdGVtIjowLCJoYXJkd2FyZSI6MCwiaW5zdGFuY2UtaWRlbnRpdHkiOjAsInJ1bnRpbWUtb3BhcXVlIjowLCJzb3VyY2VkLWRhdGEiOjAsInN0b3JhZ2Utb3BhcXVlIjowfX19fQ.sR6NzeeAeKdd_xe2iQF9uOLjXmQO7w20zXLVPKAjOLq1OTIRR8BWuGL5GcRCTonPbZIbyhdXJ4qMK4LnWEbCMw";
        boolean result = false;
        try {
            result = clientWrapper.isAttestationResultPositive(input);
        } catch (Exception e) {
            Assert.fail("Exception thrown for valid input: " + e.getMessage());
        }
        Assert.assertTrue(result);
    }
}
