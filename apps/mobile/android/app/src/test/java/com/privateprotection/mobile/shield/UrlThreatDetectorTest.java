package com.privateprotection.mobile.shield;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;

public class UrlThreatDetectorTest {

    private UrlThreatDetector detector;

    @Before
    public void setUp() {
        detector = new UrlThreatDetector();
    }

    @Test
    public void testCleanSafeUrl() {
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl("https://www.google.com/search?q=cybersecurity");
        assertEquals(UrlThreatDetector.Verdict.SAFE, res.verdict);
        assertEquals(UrlThreatDetector.ThreatType.NONE, res.threatType);
        assertTrue(res.riskScore < 30);
        assertEquals("google.com", res.domain);
    }

    @Test
    public void testDangerousSchemes() {
        UrlThreatDetector.UrlThreatResult resJs = detector.analyzeUrl("javascript:alert(document.cookie)");
        assertEquals(UrlThreatDetector.Verdict.DANGEROUS, resJs.verdict);
        assertEquals(UrlThreatDetector.ThreatType.DANGEROUS_SCHEME, resJs.threatType);
        assertTrue(resJs.riskScore >= 90);

        UrlThreatDetector.UrlThreatResult resData = detector.analyzeUrl("data:text/html,<script>window.location='https://attacker.com'</script>");
        assertEquals(UrlThreatDetector.Verdict.DANGEROUS, resData.verdict);
        assertEquals(UrlThreatDetector.ThreatType.DANGEROUS_SCHEME, resData.threatType);

        UrlThreatDetector.UrlThreatResult resBlob = detector.analyzeUrl("blob:https://evil.com/fake-uuid");
        assertEquals(UrlThreatDetector.Verdict.DANGEROUS, resBlob.verdict);

        UrlThreatDetector.UrlThreatResult resIntent = detector.analyzeUrl("intent://example.com#Intent;scheme=http;package=com.android.chrome;end");
        assertEquals(UrlThreatDetector.Verdict.DANGEROUS, resIntent.verdict);
    }

    @Test
    public void testBidiOverrideControlCharacters() {
        // Embed Right-To-Left Override \u202E
        String bidiUrl = "https://safe-domain.com/\u202Eexe.pdf";
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl(bidiUrl);
        assertEquals(UrlThreatDetector.Verdict.DANGEROUS, res.verdict);
        assertEquals(UrlThreatDetector.ThreatType.BIDI_OVERRIDE_SPOOF, res.threatType);
        assertTrue(res.indicators.contains("Bidirectional unicode control characters detected (potential spoofing)"));
    }

    @Test
    public void testPunycodeHomoglyphAttack() {
        // xn--apple-43d.com is apple with cyrillic 'a' (U+0430)
        String punycodeUrl = "https://xn--pple-43d.com/login";
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl(punycodeUrl);
        assertTrue(res.verdict == UrlThreatDetector.Verdict.SUSPICIOUS || res.verdict == UrlThreatDetector.Verdict.DANGEROUS);
        assertTrue(res.riskScore >= 60);
        assertTrue(res.indicators.stream().anyMatch(i -> i.contains("Punycode")));
    }

    @Test
    public void testDirectRawIpHost() {
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl("http://192.168.1.100/admin/login");
        assertTrue(res.riskScore >= 50);
        assertTrue(res.indicators.contains("Direct numeric IPv4 host address used instead of verified domain name"));
    }

    @Test
    public void testUserInfoSpoofing() {
        // URL with userinfo to confuse user: paypal.com@evil-site.com
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl("https://paypal.com@evil-phishing-host.com/account");
        assertTrue(res.riskScore >= 70);
        assertEquals(UrlThreatDetector.Verdict.DANGEROUS, res.verdict);
        assertTrue(res.indicators.stream().anyMatch(i -> i.contains("Userinfo section '@'")));
    }

    @Test
    public void testBrandTyposquatting() {
        // paypa1.com mimics paypal
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl("https://paypa1.com/signin");
        assertTrue(res.riskScore >= 60);
        assertTrue(res.indicators.stream().anyMatch(i -> i.contains("typosquatting") || i.contains("PayPal")));

        // g00gle.com
        UrlThreatDetector.UrlThreatResult resGoogle = detector.analyzeUrl("https://g00gle.com");
        assertTrue(resGoogle.riskScore >= 60);
    }

    @Test
    public void testCredentialHarvestingPathIndicators() {
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl("https://suspicious-unknown-site.info/wp-content/login/verify-password.php");
        assertTrue(res.riskScore >= 45);
        assertTrue(res.indicators.stream().anyMatch(i -> i.contains("Credential harvesting") || i.contains("login/password")));
    }

    @Test
    public void testExcessiveLengthUrl() {
        StringBuilder longUrl = new StringBuilder("https://example.com/search?param=");
        for (int i = 0; i < 2500; i++) {
            longUrl.append("a");
        }
        UrlThreatDetector.UrlThreatResult res = detector.analyzeUrl(longUrl.toString());
        assertTrue(res.normalizedUrl.length() <= 2048);
        assertTrue(res.indicators.stream().anyMatch(i -> i.contains("Excessive length")));
    }

    @Test
    public void testRedirectChainAnalysis() {
        // Safe redirect chain
        UrlThreatDetector.RedirectChainResult safeChain = detector.analyzeRedirectChain(Arrays.asList(
                "https://t.co/xyz123",
                "https://example.com"
        ));
        assertFalse(safeChain.isDangerous);
        assertEquals(2, safeChain.totalHops);

        // Dangerous redirect chain leading to phishing or js
        UrlThreatDetector.RedirectChainResult evilChain = detector.analyzeRedirectChain(Arrays.asList(
                "https://bit.ly/claim-prize",
                "https://redirect-intermediary.net",
                "https://paypa1-security.com/signin"
        ));
        assertTrue(evilChain.isDangerous);
        assertEquals(3, evilChain.totalHops);

        // Excessively long redirect chain (hop limit exceeded)
        UrlThreatDetector.RedirectChainResult longChain = detector.analyzeRedirectChain(Arrays.asList(
                "https://u1.com", "https://u2.com", "https://u3.com",
                "https://u4.com", "https://u5.com", "https://u6.com", "https://u7.com"
        ));
        assertTrue(longChain.isDangerous);
        assertTrue(longChain.reason.contains("Suspiciously deep redirect hop count"));
    }

    @Test
    public void testEmptyAndMalformedUrls() {
        UrlThreatDetector.UrlThreatResult nullRes = detector.analyzeUrl(null);
        assertEquals(UrlThreatDetector.Verdict.SAFE, nullRes.verdict);

        UrlThreatDetector.UrlThreatResult emptyRes = detector.analyzeUrl("   ");
        assertEquals(UrlThreatDetector.Verdict.SAFE, emptyRes.verdict);

        UrlThreatDetector.UrlThreatResult malformed = detector.analyzeUrl("http://");
        assertEquals(UrlThreatDetector.Verdict.DANGEROUS, malformed.verdict);
        assertEquals(UrlThreatDetector.ThreatType.INVALID_URL, malformed.threatType);
    }
}
