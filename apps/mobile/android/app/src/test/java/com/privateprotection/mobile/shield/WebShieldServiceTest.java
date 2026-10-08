package com.privateprotection.mobile.shield;

import android.content.Context;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class WebShieldServiceTest {

    private WebShieldService service;
    private Context mockContext;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        service = WebShieldService.getInstance(mockContext);
    }

    @Test
    public void testIsDomainBlockedPrepopulatedDomains() {
        assertTrue(service.isDomainBlocked("phishing-bank-login.com"));
        assertTrue(service.isDomainBlocked("login.phishing-bank-login.com"));
        assertTrue(service.isDomainBlocked("eicar.org"));
        assertTrue(service.isDomainBlocked("crypto-giveaway-airdrop.top"));

        assertFalse(service.isDomainBlocked("google.com"));
        assertFalse(service.isDomainBlocked("github.com"));
    }

    @Test
    public void testCustomAllowlistOverridesBlocklist() {
        String testDomain = "secure-account-update.xyz";
        assertTrue(service.isDomainBlocked(testDomain));

        service.addCustomAllowedDomain(testDomain);
        assertFalse(service.isDomainBlocked(testDomain));
    }

    @Test
    public void testAddCustomBlockedDomain() {
        String newBadDomain = "fraudulent-tax-refund.org";
        assertFalse(service.isDomainBlocked(newBadDomain));

        service.addCustomBlockedDomain(newBadDomain);
        assertTrue(service.isDomainBlocked(newBadDomain));
    }

    @Test
    public void testInspectUrlCoordinatesWithDetectorAndThreatDb() {
        // Safe domain
        UrlThreatDetector.UrlThreatResult safeRes = service.inspectUrl("https://wikipedia.org/wiki/Computer_security");
        assertEquals(UrlThreatDetector.Verdict.SAFE, safeRes.verdict);

        // Prepopulated blocked domain
        UrlThreatDetector.UrlThreatResult blockedRes = service.inspectUrl("https://paypa1-security.com/account/login");
        assertTrue(blockedRes.verdict == UrlThreatDetector.Verdict.SUSPICIOUS || blockedRes.verdict == UrlThreatDetector.Verdict.DANGEROUS);
        assertTrue(blockedRes.riskScore >= 70);
    }

    @Test
    public void testInspectRedirectChain() {
        UrlThreatDetector.RedirectChainResult chainResult = service.inspectRedirectChain(Arrays.asList(
                "https://linktr.ee/special-offer",
                "https://phishing-bank-login.com"
        ));
        assertTrue(chainResult.isDangerous);
        assertEquals(2, chainResult.totalHops);
    }

    @Test
    public void testDnsQueryRecordingMetrics() {
        service.recordDnsQuery("safe-site.com");
        service.recordDnsQuery("another-safe.org");
        service.recordBlockedQuery("phishing-bank-login.com");

        JSONObject statusJson = service.getWebShieldStatusJson();
        assertNotNull(statusJson);
        assertTrue(statusJson.optInt("totalDnsQueries", 0) >= 2);
        assertTrue(statusJson.optInt("blockedDnsQueries", 0) >= 1);
        assertTrue(statusJson.optLong("lastThreatTimestamp", 0) > 0);
    }

    @Test
    public void testPlatformCapabilityMatrixTruthfulness() {
        JSONObject statusJson = service.getWebShieldStatusJson();
        JSONObject capabilities = statusJson.optJSONObject("capabilities");
        assertNotNull(capabilities);

        assertTrue(capabilities.optBoolean("categoryA_directAndroid"));
        assertTrue(capabilities.optBoolean("categoryB_browserIntegration"));
        assertTrue(capabilities.optBoolean("categoryC_userUrlSharing"));
        assertTrue(capabilities.optBoolean("categoryD_localVpnShield"));

        // Crucial truthful assertion: Category E (unprivileged silent browser interception) is FALSE
        assertFalse(capabilities.optBoolean("categoryE_systemWideBrowserHookWithoutVpn"));
        assertNotNull(capabilities.optString("categoryE_limitationExplanation"));
        assertTrue(capabilities.optString("categoryE_limitationExplanation").contains("sandbox"));
    }

    @Test
    public void testVpnStateManagement() {
        service.setVpnActive(true);
        assertTrue(service.isVpnActive());

        service.setAnotherVpnActive(true);
        assertTrue(service.isAnotherVpnActive());

        service.setVpnActive(false);
        assertFalse(service.isVpnActive());
    }
}
