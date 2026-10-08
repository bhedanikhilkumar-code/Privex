package com.privateprotection.mobile.shield;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import com.privateprotection.mobile.MainActivity;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

/**
 * PreThreatWarningCoordinator (Phase T7):
 *
 * Evidence-Backed Predictive Pre-Threat Warning Engine for Android:
 * - Evaluates high-risk candidates across URLs (T6), Files/Downloads (T3/T5), and App Packages (T2).
 * - Distinguishes evidence confidence: CONFIRMED_MALWARE vs STRONG_SUSPICION vs HEURISTIC_ANOMALY.
 * - Surfaces grounded technical detection triggers (what triggered the warning).
 * - Articulates plain-language potential consequences and factual impact.
 * - Designates unambiguous recommended safe defaults (Go Back, Delete, Cancel Install).
 * - Configures friction-gate countdown parameters (5-second delay for DANGEROUS bypass).
 * - Provides rate-limiting and deduplication to avoid warning fatigue.
 * - Dispatches high-priority Android notification banners linking directly to warning modals.
 * - Records structured decision telemetry strictly locally.
 *
 * CANONICAL CONSTITUTIONAL INVARIANTS:
 * - Content is analyzed strictly as DATA, never executed as code.
 * - Warnings are strictly EVIDENCE-BACKED, never fear-based or speculative.
 * - 100% on-device processing. Zero user payload transmission off-device.
 */
public class PreThreatWarningCoordinator {
    private static final String TAG = "PreThreatCoordinator";

    public static final String NOTIFICATION_CHANNEL_ID = "pp_pre_threat_warnings";
    private static final String NOTIFICATION_CHANNEL_NAME = "High-Priority Pre-Threat Warnings";
    private static final int NOTIFICATION_ID_BASE = 5000;
    private static final long DEDUPLICATION_WINDOW_MS = 30000; // 30 seconds
    private static final int MAX_DECISION_HISTORY = 100;

    private static volatile PreThreatWarningCoordinator instance;

    private final Context appContext;
    private final Map<String, Long> lastWarningTimestamps = new HashMap<>();
    private final Deque<JSONObject> decisionHistory = new ArrayDeque<>();
    private final Object stateLock = new Object();

    public enum ConfidenceLevel {
        CONFIRMED_MALWARE,
        STRONG_SUSPICION,
        HEURISTIC_ANOMALY
    }

    public enum PreThreatAction {
        GO_BACK,
        CANCEL_INSTALL,
        DELETE_DOWNLOAD,
        QUARANTINE,
        RESCAN,
        INSPECT_DETAILS,
        CONTINUE_AT_OWN_RISK
    }

    private PreThreatWarningCoordinator(Context context) {
        this.appContext = context.getApplicationContext();
        ensureNotificationChannel();
    }

    public static PreThreatWarningCoordinator getInstance(Context context) {
        if (instance == null) {
            synchronized (PreThreatWarningCoordinator.class) {
                if (instance == null) {
                    instance = new PreThreatWarningCoordinator(context);
                }
            }
        }
        return instance;
    }

    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) appContext.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                NotificationChannel channel = new NotificationChannel(
                        NOTIFICATION_CHANNEL_ID,
                        NOTIFICATION_CHANNEL_NAME,
                        NotificationManager.IMPORTANCE_HIGH
                );
                channel.setDescription("Immediate evidence-backed warnings prior to opening or executing untrusted content");
                channel.enableVibration(true);
                channel.setVibrationPattern(new long[]{0, 250, 150, 250});
                nm.createNotificationChannel(channel);
            }
        }
    }

    /**
     * Synthesizes a PreThreatWarningPayload from URL threat analysis (Phase T6).
     */
    public JSONObject synthesizeUrlWarning(UrlThreatDetector.UrlThreatResult urlResult) {
        if (urlResult == null) {
            return null;
        }

        JSONObject warning = new JSONObject();
        try {
            String url = urlResult.normalizedUrl != null ? urlResult.normalizedUrl : "";
            int score = urlResult.riskScore;
            UrlThreatDetector.Verdict verdict = urlResult.verdict;
            UrlThreatDetector.ThreatType threatType = urlResult.threatType;

            String warningId = "warn-url-" + System.currentTimeMillis() + "-" + Math.abs(url.hashCode() % 100000);

            // 1. Evidence Confidence Level
            ConfidenceLevel confidence;
            if (threatType == UrlThreatDetector.ThreatType.DANGEROUS_SCHEME || score >= 90) {
                confidence = ConfidenceLevel.CONFIRMED_MALWARE;
            } else if (threatType == UrlThreatDetector.ThreatType.HOMOGLYPH_ATTACK
                    || threatType == UrlThreatDetector.ThreatType.PUNYCODE_SPOOF
                    || threatType == UrlThreatDetector.ThreatType.CREDENTIAL_HARVESTING
                    || score >= 70) {
                confidence = ConfidenceLevel.STRONG_SUSPICION;
            } else {
                confidence = ConfidenceLevel.HEURISTIC_ANOMALY;
            }

            // 2. What Detected (Grounded statement)
            String whatDetected;
            switch (threatType) {
                case DANGEROUS_SCHEME:
                    whatDetected = "Dangerous executable URI scheme (" + (urlResult.scheme != null ? urlResult.scheme : "unknown")
                            + ":) detected attempting script or system execution outside browser sandboxing.";
                    break;
                case HOMOGLYPH_ATTACK:
                case PUNYCODE_SPOOF:
                    whatDetected = "Deceptive lookalike domain using internationalized characters to impersonate legitimate services ("
                            + (urlResult.domain != null ? urlResult.domain : "unknown") + ").";
                    break;
                case TYPOSQUATTING:
                    whatDetected = "Typosquatting permutation identified mimicking an authentic platform ("
                            + (urlResult.domain != null ? urlResult.domain : "unknown") + ").";
                    break;
                case CREDENTIAL_HARVESTING:
                    whatDetected = "Credential harvesting patterns and login authentication impersonation tokens detected in URL structure.";
                    break;
                case SUSPICIOUS_IP_HOST:
                    whatDetected = "Direct numeric IP address host utilized in place of a verifiable domain identity.";
                    break;
                case USERINFO_SPOOF:
                    whatDetected = "Userinfo authentication prefix embedded in URL to camouflage the authentic destination host.";
                    break;
                case BIDI_OVERRIDE_SPOOF:
                    whatDetected = "Bi-directional Unicode override control characters detected attempting to invert domain name display.";
                    break;
                default:
                    whatDetected = urlResult.explanation != null && !urlResult.explanation.isEmpty()
                            ? urlResult.explanation
                            : "Heuristic risk indicators identified during on-device lexical URL inspection.";
                    break;
            }

            // 3. Plain-Language Potential Consequences
            String consequences;
            if (threatType == UrlThreatDetector.ThreatType.DANGEROUS_SCHEME) {
                consequences = "Opening this link may execute unauthorized script code or trigger unintended application actions on your device.";
            } else if (threatType == UrlThreatDetector.ThreatType.HOMOGLYPH_ATTACK
                    || threatType == UrlThreatDetector.ThreatType.TYPOSQUATTING
                    || threatType == UrlThreatDetector.ThreatType.CREDENTIAL_HARVESTING) {
                consequences = "Visiting this deceptive site may allow attackers to steal your account passwords, personal information, or session credentials.";
            } else if (threatType == UrlThreatDetector.ThreatType.SUSPICIOUS_IP_HOST) {
                consequences = "Connecting directly to an unverified IP host bypasses security certificate checks and may route you to hostile infrastructure.";
            } else {
                consequences = "Interacting with this link may expose your browser to fraudulent content or deceptive downloads.";
            }

            // 4. Safe Default Recommendation
            PreThreatAction recommendedAction = PreThreatAction.GO_BACK;

            // 5. Supported Choices
            JSONArray supportedChoices = new JSONArray();
            supportedChoices.put(PreThreatAction.GO_BACK.name());
            supportedChoices.put(PreThreatAction.INSPECT_DETAILS.name());
            supportedChoices.put(PreThreatAction.CONTINUE_AT_OWN_RISK.name());

            // 6. Evidence List
            JSONArray evidenceList = new JSONArray();
            if (urlResult.indicators != null) {
                for (String ind : urlResult.indicators) {
                    JSONObject ev = new JSONObject();
                    ev.put("code", threatType.name());
                    ev.put("severity", verdict == UrlThreatDetector.Verdict.DANGEROUS ? "CRITICAL" : "HIGH");
                    ev.put("description", ind);
                    evidenceList.put(ev);
                }
            }

            boolean requiresFrictionGate = verdict == UrlThreatDetector.Verdict.DANGEROUS || score >= 75;
            int frictionSec = requiresFrictionGate ? 5 : 0;

            warning.put("warningId", warningId);
            warning.put("targetType", "URL");
            warning.put("targetIdentifier", url);
            warning.put("riskScore", score);
            warning.put("verdict", verdict.name());
            warning.put("confidenceLevel", confidence.name());
            warning.put("whatDetected", whatDetected);
            warning.put("potentialConsequences", consequences);
            warning.put("recommendedAction", recommendedAction.name());
            warning.put("supportedChoices", supportedChoices);
            warning.put("evidenceDetails", evidenceList);
            warning.put("requiresFrictionGate", requiresFrictionGate);
            warning.put("frictionGateSeconds", frictionSec);
            warning.put("timestamp", System.currentTimeMillis());

        } catch (JSONException e) {
            Log.e(TAG, "Failed to assemble URL pre-threat warning", e);
            return null;
        }
        return warning;
    }

    /**
     * Synthesizes a PreThreatWarningPayload from Universal File / Download inspection (Phases T3 / T5).
     */
    public JSONObject synthesizeFileWarning(JSONObject fileInspectionJson) {
        if (fileInspectionJson == null) {
            return null;
        }

        JSONObject warning = new JSONObject();
        try {
            int score = fileInspectionJson.optInt("score", 0);
            String verdict = fileInspectionJson.optString("verdict", "CAUTION");
            JSONObject identity = fileInspectionJson.optJSONObject("fileIdentity");
            String fileName = identity != null ? identity.optString("fileName", "unnamed_file") : "unnamed_file";
            String filePath = identity != null ? identity.optString("uriString", fileName) : fileName;
            JSONArray evidenceArray = fileInspectionJson.optJSONArray("evidence");

            String warningId = "warn-file-" + System.currentTimeMillis() + "-" + Math.abs(filePath.hashCode() % 100000);

            // 1. Evidence Confidence Level
            boolean hasMalwareTest = false;
            boolean hasZipBombOrTraversal = false;
            boolean hasEmbeddedExec = false;

            if (evidenceArray != null) {
                for (int i = 0; i < evidenceArray.length(); i++) {
                    JSONObject ev = evidenceArray.optJSONObject(i);
                    if (ev != null) {
                        String code = ev.optString("code", "");
                        if ("EICAR_TEST_PAYLOAD".equals(code)) {
                            hasMalwareTest = true;
                        } else if ("PATH_TRAVERSAL_DETECTED".equals(code) || "ARCHIVE_ZIP_BOMB".equals(code)) {
                            hasZipBombOrTraversal = true;
                        } else if ("APK_SUSPICIOUS_EMBEDDED_PAYLOAD".equals(code) || "ARCHIVE_EMBEDDED_EXECUTABLES".equals(code)) {
                            hasEmbeddedExec = true;
                        }
                    }
                }
            }

            ConfidenceLevel confidence;
            if (hasMalwareTest || hasZipBombOrTraversal || score >= 90) {
                confidence = ConfidenceLevel.CONFIRMED_MALWARE;
            } else if (hasEmbeddedExec || score >= 70) {
                confidence = ConfidenceLevel.STRONG_SUSPICION;
            } else {
                confidence = ConfidenceLevel.HEURISTIC_ANOMALY;
            }

            // 2. What Detected
            String whatDetected;
            if (hasMalwareTest) {
                whatDetected = "Verified malware signature (EICAR standard antivirus test pattern) detected in file headers.";
            } else if (hasZipBombOrTraversal) {
                whatDetected = "Archive contains malicious path traversal sequence (../) or hazardous compression ratio (zip bomb).";
            } else if (hasEmbeddedExec) {
                whatDetected = "Hidden secondary executable binaries or dynamic scripts detected embedded inside the file archive.";
            } else if ("DANGEROUS".equals(verdict)) {
                whatDetected = "High-risk executable format or binary signature mismatch detected during on-device header inspection.";
            } else {
                whatDetected = "Heuristic file anomalies or unverified executable extensions detected in downloaded content.";
            }

            // 3. Plain-Language Consequences
            String consequences;
            if (hasZipBombOrTraversal) {
                consequences = "Extracting this archive could overwrite protected app files or exhaust your device storage.";
            } else if (hasMalwareTest || hasEmbeddedExec || "DANGEROUS".equals(verdict)) {
                consequences = "Opening or running this file could execute unauthorized binary code or compromise private device data.";
            } else {
                consequences = "Running an unverified file from an external source may expose your device to unexpected behavior.";
            }

            // 4. Safe Default Recommendation
            PreThreatAction recommendedAction = PreThreatAction.DELETE_DOWNLOAD;

            // 5. Supported Choices
            JSONArray supportedChoices = new JSONArray();
            supportedChoices.put(PreThreatAction.DELETE_DOWNLOAD.name());
            supportedChoices.put(PreThreatAction.QUARANTINE.name());
            supportedChoices.put(PreThreatAction.INSPECT_DETAILS.name());
            supportedChoices.put(PreThreatAction.CONTINUE_AT_OWN_RISK.name());

            boolean requiresFrictionGate = "DANGEROUS".equals(verdict) || score >= 75;
            int frictionSec = requiresFrictionGate ? 5 : 0;

            warning.put("warningId", warningId);
            warning.put("targetType", "DOWNLOAD");
            warning.put("targetIdentifier", fileName);
            warning.put("riskScore", score);
            warning.put("verdict", verdict);
            warning.put("confidenceLevel", confidence.name());
            warning.put("whatDetected", whatDetected);
            warning.put("potentialConsequences", consequences);
            warning.put("recommendedAction", recommendedAction.name());
            warning.put("supportedChoices", supportedChoices);
            warning.put("evidenceDetails", evidenceArray != null ? evidenceArray : new JSONArray());
            warning.put("requiresFrictionGate", requiresFrictionGate);
            warning.put("frictionGateSeconds", frictionSec);
            warning.put("timestamp", System.currentTimeMillis());

        } catch (JSONException e) {
            Log.e(TAG, "Failed to assemble file pre-threat warning", e);
            return null;
        }
        return warning;
    }

    /**
     * Synthesizes a PreThreatWarningPayload from Package Audit inspection (Phase T2).
     */
    public JSONObject synthesizePackageWarning(JSONObject packageAuditJson) {
        if (packageAuditJson == null) {
            return null;
        }

        JSONObject warning = new JSONObject();
        try {
            int score = packageAuditJson.optInt("score", 0);
            String verdict = packageAuditJson.optString("verdict", "CAUTION");
            String packageName = packageAuditJson.optString("packageName", "unknown.package");
            String appLabel = packageAuditJson.optString("appLabel", packageName);
            boolean isSideloaded = packageAuditJson.optBoolean("isSideloaded", false);
            JSONArray evidenceArray = packageAuditJson.optJSONArray("evidence");

            String warningId = "warn-pkg-" + System.currentTimeMillis() + "-" + Math.abs(packageName.hashCode() % 100000);

            // 1. Evidence Confidence Level
            boolean hasEmbeddedPayloads = false;
            boolean hasCriticalPerms = false;

            if (evidenceArray != null) {
                for (int i = 0; i < evidenceArray.length(); i++) {
                    JSONObject ev = evidenceArray.optJSONObject(i);
                    if (ev != null) {
                        String code = ev.optString("code", "");
                        if ("APK_SUSPICIOUS_EMBEDDED_PAYLOAD".equals(code)) {
                            hasEmbeddedPayloads = true;
                        } else if ("DANGEROUS_PERMISSIONS_CLUSTER".equals(code) || "EXCESSIVE_PERMISSIONS".equals(code)) {
                            hasCriticalPerms = true;
                        }
                    }
                }
            }

            ConfidenceLevel confidence;
            if (hasEmbeddedPayloads || score >= 80) {
                confidence = ConfidenceLevel.CONFIRMED_MALWARE;
            } else if (hasCriticalPerms || score >= 50) {
                confidence = ConfidenceLevel.STRONG_SUSPICION;
            } else {
                confidence = ConfidenceLevel.HEURISTIC_ANOMALY;
            }

            // 2. What Detected
            String whatDetected;
            if (hasEmbeddedPayloads) {
                whatDetected = "Application package contains embedded dynamic droppers or executable binaries (" + appLabel + ").";
            } else if (isSideloaded && hasCriticalPerms) {
                whatDetected = "Sideloaded application (" + appLabel + ") outside Google Play requesting high-risk system permissions.";
            } else if ("DANGEROUS".equals(verdict)) {
                whatDetected = "High-risk package profile and dangerous permission combinations detected for " + appLabel + ".";
            } else {
                whatDetected = "Sideloaded application package with unverified installation origin (" + appLabel + ").";
            }

            // 3. Consequences
            String consequences;
            if (hasEmbeddedPayloads || "DANGEROUS".equals(verdict)) {
                consequences = "Installing this package could allow unauthorized background processes, keystroke monitoring, or data exfiltration.";
            } else if (hasCriticalPerms) {
                consequences = "Granting sensitive permissions to this app may allow it to access private messages, contacts, or location without oversight.";
            } else {
                consequences = "Unverified sideloaded apps bypass Google Play Protect verification and may contain unvetted components.";
            }

            // 4. Safe Default Recommendation
            PreThreatAction recommendedAction = PreThreatAction.CANCEL_INSTALL;

            // 5. Supported Choices
            JSONArray supportedChoices = new JSONArray();
            supportedChoices.put(PreThreatAction.CANCEL_INSTALL.name());
            supportedChoices.put(PreThreatAction.INSPECT_DETAILS.name());
            supportedChoices.put(PreThreatAction.CONTINUE_AT_OWN_RISK.name());

            boolean requiresFrictionGate = "DANGEROUS".equals(verdict) || score >= 75;
            int frictionSec = requiresFrictionGate ? 5 : 0;

            warning.put("warningId", warningId);
            warning.put("targetType", "APP_PACKAGE");
            warning.put("targetIdentifier", packageName);
            warning.put("riskScore", score);
            warning.put("verdict", verdict);
            warning.put("confidenceLevel", confidence.name());
            warning.put("whatDetected", whatDetected);
            warning.put("potentialConsequences", consequences);
            warning.put("recommendedAction", recommendedAction.name());
            warning.put("supportedChoices", supportedChoices);
            warning.put("evidenceDetails", evidenceArray != null ? evidenceArray : new JSONArray());
            warning.put("requiresFrictionGate", requiresFrictionGate);
            warning.put("frictionGateSeconds", frictionSec);
            warning.put("timestamp", System.currentTimeMillis());

        } catch (JSONException e) {
            Log.e(TAG, "Failed to assemble package pre-threat warning", e);
            return null;
        }
        return warning;
    }

    /**
     * Rate limits warnings to prevent alert fatigue. Returns true if throttled.
     */
    public boolean shouldThrottleWarning(String targetIdentifier) {
        if (targetIdentifier == null || targetIdentifier.trim().isEmpty()) {
            return false;
        }
        synchronized (stateLock) {
            long now = System.currentTimeMillis();
            Long last = lastWarningTimestamps.get(targetIdentifier);
            if (last != null && (now - last) < DEDUPLICATION_WINDOW_MS) {
                Log.d(TAG, "Throttling duplicate pre-threat warning for " + targetIdentifier);
                return true;
            }
            lastWarningTimestamps.put(targetIdentifier, now);
            return false;
        }
    }

    /**
     * Dispatches an Android Notification for a synthesized PreThreatWarningPayload.
     */
    public boolean dispatchPreThreatNotification(JSONObject warningJson) {
        if (warningJson == null) {
            return false;
        }

        String targetIdentifier = warningJson.optString("targetIdentifier", "Unknown Target");
        if (shouldThrottleWarning(targetIdentifier)) {
            return false;
        }

        String targetType = warningJson.optString("targetType", "THREAT");
        String verdict = warningJson.optString("verdict", "CAUTION");
        String confidence = warningJson.optString("confidenceLevel", "HEURISTIC_ANOMALY");
        String whatDetected = warningJson.optString("whatDetected", "Threat indicators detected.");
        String recommendedAction = warningJson.optString("recommendedAction", "GO_BACK");

        Intent intent = new Intent(appContext, MainActivity.class);
        intent.setAction("PRE_THREAT_WARNING");
        intent.putExtra("warning_payload", warningJson.toString());
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        int reqCode = Math.abs(targetIdentifier.hashCode() % 10000);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pendingIntent = PendingIntent.getActivity(appContext, reqCode, intent, flags);

        String title = "🛑 Security Warning: " + verdict + " (" + confidence + ")";
        String summary = targetType + ": " + targetIdentifier + "\n" + whatDetected + "\nRecommended: " + recommendedAction;

        NotificationCompat.Builder builder = new NotificationCompat.Builder(appContext, NOTIFICATION_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(title)
                .setContentText(whatDetected)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(summary))
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent);

        try {
            NotificationManagerCompat nmc = NotificationManagerCompat.from(appContext);
            nmc.notify(NOTIFICATION_ID_BASE + (reqCode % 500), builder.build());
            return true;
        } catch (SecurityException se) {
            Log.w(TAG, "Notification permission missing for pre-threat notification", se);
            return false;
        } catch (Exception e) {
            Log.e(TAG, "Failed to dispatch pre-threat notification", e);
            return false;
        }
    }

    /**
     * Records a pre-threat user decision in bounded local volatile memory.
     */
    public boolean recordDecision(String warningId, String targetIdentifier, String selectedAction, boolean bypassed) {
        if (warningId == null || selectedAction == null) {
            return false;
        }
        synchronized (stateLock) {
            try {
                JSONObject dec = new JSONObject();
                dec.put("warningId", warningId);
                dec.put("targetIdentifier", targetIdentifier != null ? targetIdentifier : "");
                dec.put("selectedAction", selectedAction);
                dec.put("bypassedWithFrictionGate", bypassed);
                dec.put("timestamp", System.currentTimeMillis());

                if (decisionHistory.size() >= MAX_DECISION_HISTORY) {
                    decisionHistory.pollFirst();
                }
                decisionHistory.addLast(dec);
                return true;
            } catch (JSONException e) {
                Log.e(TAG, "Failed to record decision", e);
                return false;
            }
        }
    }

    /**
     * Returns the recent decision history.
     */
    public JSONArray getDecisionHistory() {
        synchronized (stateLock) {
            JSONArray arr = new JSONArray();
            for (JSONObject item : decisionHistory) {
                arr.put(item);
            }
            return arr;
        }
    }

    /**
     * Clears cached deduplication records and decision history (e.g. for testing or user-initiated reset).
     */
    public void clearHistory() {
        synchronized (stateLock) {
            lastWarningTimestamps.clear();
            decisionHistory.clear();
        }
    }
}
