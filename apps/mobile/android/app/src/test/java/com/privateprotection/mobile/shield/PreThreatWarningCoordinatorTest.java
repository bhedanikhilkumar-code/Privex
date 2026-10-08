package com.privateprotection.mobile.shield;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class PreThreatWarningCoordinatorTest {

    private PreThreatWarningCoordinator coordinator;
    private Context mockContext;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        coordinator = PreThreatWarningCoordinator.getInstance(mockContext);
        coordinator.clearHistory();
    }

    @Test
    public void testSynthesizeUrlWarningForDangerousScheme() {
        UrlThreatDetector.UrlThreatResult result = new UrlThreatDetector.UrlThreatResult(
                "javascript:alert(1)",
                null,
                "javascript",
                100,
                UrlThreatDetector.Verdict.DANGEROUS,
                UrlThreatDetector.ThreatType.DANGEROUS_SCHEME,
                Collections.singletonList("Executable javascript: URI scheme"),
                "Dangerous executable URI scheme"
        );

        JSONObject warning = coordinator.synthesizeUrlWarning(result);
        assertNotNull(warning);
        assertEquals("URL", warning.optString("targetType"));
        assertEquals("javascript:alert(1)", warning.optString("targetIdentifier"));
        assertEquals("DANGEROUS", warning.optString("verdict"));
        assertEquals("CONFIRMED_MALWARE", warning.optString("confidenceLevel"));
        assertEquals("GO_BACK", warning.optString("recommendedAction"));
        assertTrue(warning.optBoolean("requiresFrictionGate"));
        assertEquals(5, warning.optInt("frictionGateSeconds"));
        assertTrue(warning.optString("whatDetected").contains("Dangerous executable URI scheme"));
        assertTrue(warning.optString("potentialConsequences").contains("unauthorized script code"));

        JSONArray choices = warning.optJSONArray("supportedChoices");
        assertNotNull(choices);
        assertTrue(choices.toString().contains("GO_BACK"));
        assertTrue(choices.toString().contains("CONTINUE_AT_OWN_RISK"));
    }

    @Test
    public void testSynthesizeUrlWarningForHomoglyphAttack() {
        UrlThreatDetector.UrlThreatResult result = new UrlThreatDetector.UrlThreatResult(
                "https://xn--pypal-4ve.com/signin",
                "xn--pypal-4ve.com",
                "https",
                85,
                UrlThreatDetector.Verdict.DANGEROUS,
                UrlThreatDetector.ThreatType.HOMOGLYPH_ATTACK,
                Arrays.asList("IDN Cyrillic homoglyph lookalike", "Spoofs brand paypal"),
                "Homoglyph spoofing PayPal"
        );

        JSONObject warning = coordinator.synthesizeUrlWarning(result);
        assertNotNull(warning);
        assertEquals("URL", warning.optString("targetType"));
        assertEquals("STRONG_SUSPICION", warning.optString("confidenceLevel"));
        assertTrue(warning.optString("whatDetected").contains("lookalike domain"));
        assertTrue(warning.optString("potentialConsequences").contains("steal your account passwords"));
        assertEquals("GO_BACK", warning.optString("recommendedAction"));
    }

    @Test
    public void testSynthesizeUrlWarningForIpHost() {
        UrlThreatDetector.UrlThreatResult result = new UrlThreatDetector.UrlThreatResult(
                "http://192.168.1.100/login",
                "192.168.1.100",
                "http",
                60,
                UrlThreatDetector.Verdict.SUSPICIOUS,
                UrlThreatDetector.ThreatType.SUSPICIOUS_IP_HOST,
                Collections.singletonList("Direct numeric IP host"),
                "Direct IP host"
        );

        JSONObject warning = coordinator.synthesizeUrlWarning(result);
        assertNotNull(warning);
        assertEquals("HEURISTIC_ANOMALY", warning.optString("confidenceLevel"));
        assertTrue(warning.optString("whatDetected").contains("Direct numeric IP address"));
        assertTrue(warning.optString("potentialConsequences").contains("unverified IP host"));
    }

    @Test
    public void testSynthesizeFileWarningForEicar() throws Exception {
        JSONObject fileJson = new JSONObject();
        JSONObject identity = new JSONObject();
        identity.put("fileName", "eicar.com");
        identity.put("uriString", "/storage/emulated/0/Download/eicar.com");
        fileJson.put("fileIdentity", identity);
        fileJson.put("score", 100);
        fileJson.put("verdict", "DANGEROUS");

        JSONArray evidence = new JSONArray();
        JSONObject ev = new JSONObject();
        ev.put("code", "EICAR_TEST_PAYLOAD");
        ev.put("severity", "CRITICAL");
        ev.put("description", "Antivirus test pattern");
        evidence.put(ev);
        fileJson.put("evidence", evidence);

        JSONObject warning = coordinator.synthesizeFileWarning(fileJson);
        assertNotNull(warning);
        assertEquals("DOWNLOAD", warning.optString("targetType"));
        assertEquals("eicar.com", warning.optString("targetIdentifier"));
        assertEquals("CONFIRMED_MALWARE", warning.optString("confidenceLevel"));
        assertEquals("DELETE_DOWNLOAD", warning.optString("recommendedAction"));
        assertTrue(warning.optBoolean("requiresFrictionGate"));
        assertEquals(5, warning.optInt("frictionGateSeconds"));
        assertTrue(warning.optString("whatDetected").contains("EICAR standard antivirus test pattern"));

        JSONArray choices = warning.optJSONArray("supportedChoices");
        assertTrue(choices.toString().contains("DELETE_DOWNLOAD"));
        assertTrue(choices.toString().contains("QUARANTINE"));
    }

    @Test
    public void testSynthesizeFileWarningForZipBomb() throws Exception {
        JSONObject fileJson = new JSONObject();
        JSONObject identity = new JSONObject();
        identity.put("fileName", "nested_archive.zip");
        fileJson.put("fileIdentity", identity);
        fileJson.put("score", 95);
        fileJson.put("verdict", "DANGEROUS");

        JSONArray evidence = new JSONArray();
        JSONObject ev = new JSONObject();
        ev.put("code", "ARCHIVE_ZIP_BOMB");
        ev.put("severity", "CRITICAL");
        ev.put("description", "Compression bomb detected");
        evidence.put(ev);
        fileJson.put("evidence", evidence);

        JSONObject warning = coordinator.synthesizeFileWarning(fileJson);
        assertNotNull(warning);
        assertEquals("CONFIRMED_MALWARE", warning.optString("confidenceLevel"));
        assertTrue(warning.optString("whatDetected").contains("hazardous compression ratio"));
        assertTrue(warning.optString("potentialConsequences").contains("exhaust your device storage"));
    }

    @Test
    public void testSynthesizePackageWarningForEmbeddedPayload() throws Exception {
        JSONObject pkgJson = new JSONObject();
        pkgJson.put("packageName", "com.suspicious.trojan");
        pkgJson.put("appLabel", "TrojanApp");
        pkgJson.put("score", 85);
        pkgJson.put("verdict", "DANGEROUS");
        pkgJson.put("isSideloaded", true);

        JSONArray evidence = new JSONArray();
        JSONObject ev = new JSONObject();
        ev.put("code", "APK_SUSPICIOUS_EMBEDDED_PAYLOAD");
        ev.put("severity", "HIGH");
        ev.put("description", "Dynamic dropper detected in assets");
        evidence.put(ev);
        pkgJson.put("evidence", evidence);

        JSONObject warning = coordinator.synthesizePackageWarning(pkgJson);
        assertNotNull(warning);
        assertEquals("APP_PACKAGE", warning.optString("targetType"));
        assertEquals("com.suspicious.trojan", warning.optString("targetIdentifier"));
        assertEquals("CONFIRMED_MALWARE", warning.optString("confidenceLevel"));
        assertEquals("CANCEL_INSTALL", warning.optString("recommendedAction"));
        assertTrue(warning.optBoolean("requiresFrictionGate"));
        assertTrue(warning.optString("whatDetected").contains("embedded dynamic droppers"));
        assertTrue(warning.optString("potentialConsequences").contains("unauthorized background processes"));
    }

    @Test
    public void testSynthesizePackageWarningForDangerousPermissions() throws Exception {
        JSONObject pkgJson = new JSONObject();
        pkgJson.put("packageName", "com.unknown.tool");
        pkgJson.put("appLabel", "FreeCalculator");
        pkgJson.put("score", 60);
        pkgJson.put("verdict", "SUSPICIOUS");
        pkgJson.put("isSideloaded", true);

        JSONArray evidence = new JSONArray();
        JSONObject ev = new JSONObject();
        ev.put("code", "DANGEROUS_PERMISSIONS_CLUSTER");
        ev.put("severity", "HIGH");
        ev.put("description", "Requests SMS, Contacts, and Location");
        evidence.put(ev);
        pkgJson.put("evidence", evidence);

        JSONObject warning = coordinator.synthesizePackageWarning(pkgJson);
        assertNotNull(warning);
        assertEquals("STRONG_SUSPICION", warning.optString("confidenceLevel"));
        assertEquals("CANCEL_INSTALL", warning.optString("recommendedAction"));
        assertTrue(warning.optString("whatDetected").contains("high-risk system permissions"));
        assertTrue(warning.optString("potentialConsequences").contains("private messages"));
    }

    @Test
    public void testRateLimitingDeduplication() {
        String testTarget = "https://phishing.example.com";
        assertFalse(coordinator.shouldThrottleWarning(testTarget));
        // Immediate second call for same target is throttled
        assertTrue(coordinator.shouldThrottleWarning(testTarget));
        // Different target is not throttled
        assertFalse(coordinator.shouldThrottleWarning("https://different-target.com"));
    }

    @Test
    public void testRecordDecisionAndHistory() {
        boolean recorded1 = coordinator.recordDecision("warn-1", "https://bad.com", "GO_BACK", false);
        boolean recorded2 = coordinator.recordDecision("warn-2", "com.bad.app", "CONTINUE_AT_OWN_RISK", true);

        assertTrue(recorded1);
        assertTrue(recorded2);

        JSONArray history = coordinator.getDecisionHistory();
        assertEquals(2, history.length());

        JSONObject item0 = history.optJSONObject(0);
        assertEquals("warn-1", item0.optString("warningId"));
        assertEquals("GO_BACK", item0.optString("selectedAction"));
        assertFalse(item0.optBoolean("bypassedWithFrictionGate"));

        JSONObject item1 = history.optJSONObject(1);
        assertEquals("warn-2", item1.optString("warningId"));
        assertEquals("CONTINUE_AT_OWN_RISK", item1.optString("selectedAction"));
        assertTrue(item1.optBoolean("bypassedWithFrictionGate"));
    }

    @Test
    public void testFailClosedNullHandling() {
        assertNull(coordinator.synthesizeUrlWarning(null));
        assertNull(coordinator.synthesizeFileWarning(null));
        assertNull(coordinator.synthesizePackageWarning(null));
        assertFalse(coordinator.recordDecision(null, null, null, false));
    }
}
