package com.privateprotection.mobile.shield;

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Phase T8: Secure Password & Passphrase Generator for Android
 * 
 * Constitutional Invariants:
 * 1. CSPRNG Only: Uses java.security.SecureRandom exclusively.
 * 2. Unbiased Sampling: Implements rejection sampling threshold to eliminate modulo bias.
 * 3. Guaranteed Pool Representation: At least 1 character from every active pool is picked.
 * 4. Distinct Passphrase Logic: Entropy calculated via wordlist size (C * log2(W)), not character formula.
 * 5. Sensitive Clipboard Handling: Sets ClipDescription.EXTRA_IS_SENSITIVE on Android 13+ (API 33+)
 *    and schedules automatic clipboard clearance after 60 seconds.
 * 6. Zero Persistence & Zero Logging: Generated secrets are never logged or stored.
 */
public class SecurePasswordGenerator {
    private static final String TAG = "SecurePasswordGen";
    private static volatile SecureRandom secureRandom;

    private static final String UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGIT_CHARS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    private static final String SIMILAR_CHARS = "IOlo01";
    private static final String AMBIGUOUS_SPECIALS = "{}[]()/\\'\"`~,;:.<>";

    private static final long CLIPBOARD_AUTOCLEAR_DELAY_MS = 60_000L; // 60 seconds

    private final Context context;

    public SecurePasswordGenerator(Context context) {
        this.context = context.getApplicationContext();
    }

    private static SecureRandom getSecureRandom() {
        if (secureRandom == null) {
            synchronized (SecurePasswordGenerator.class) {
                if (secureRandom == null) {
                    secureRandom = new SecureRandom();
                }
            }
        }
        return secureRandom;
    }

    /**
     * Unbiased rejection sampling for integer in range [0, bound - 1].
     */
    public static int nextIntUnbiased(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be positive: " + bound);
        }
        if (bound == 1) {
            return 0;
        }

        SecureRandom rng = getSecureRandom();
        // 2^31 - 1 is Integer.MAX_VALUE. Rejection threshold:
        int limit = Integer.MAX_VALUE - (Integer.MAX_VALUE % bound);
        while (true) {
            int val = rng.nextInt() & Integer.MAX_VALUE; // non-negative 31-bit integer
            if (val < limit) {
                return val % bound;
            }
        }
    }

    /**
     * Generates a character-based password adhering to options JSON.
     */
    public JSONObject generatePassword(JSONObject options) {
        JSONObject result = new JSONObject();
        try {
            int length = options.optInt("length", 20);
            length = Math.max(12, Math.min(128, length));

            boolean useUppercase = options.optBoolean("useUppercase", true);
            boolean useLowercase = options.optBoolean("useLowercase", true);
            boolean useNumbers = options.optBoolean("useNumbers", true);
            boolean useSpecial = options.optBoolean("useSpecial", true);
            boolean avoidAmbiguous = options.optBoolean("avoidAmbiguous", false);
            boolean avoidSimilar = options.optBoolean("avoidSimilar", false);

            String upper = useUppercase ? filterChars(UPPERCASE_CHARS, avoidSimilar, false) : "";
            String lower = useLowercase ? filterChars(LOWERCASE_CHARS, avoidSimilar, false) : "";
            String numbers = useNumbers ? filterChars(DIGIT_CHARS, avoidSimilar, false) : "";
            String special = useSpecial ? filterChars(SPECIAL_CHARS, false, avoidAmbiguous) : "";

            List<String> enabledPools = new ArrayList<>();
            if (!upper.isEmpty()) enabledPools.add(upper);
            if (!lower.isEmpty()) enabledPools.add(lower);
            if (!numbers.isEmpty()) enabledPools.add(numbers);
            if (!special.isEmpty()) enabledPools.add(special);

            if (enabledPools.isEmpty()) {
                result.put("error", "At least one character group must be selected.");
                return result;
            }

            StringBuilder combinedPool = new StringBuilder();
            for (String pool : enabledPools) {
                combinedPool.append(pool);
            }
            int poolSize = combinedPool.length();

            List<Character> selectedChars = new ArrayList<>();
            // Guarantee at least 1 character from each enabled pool
            for (String pool : enabledPools) {
                int idx = nextIntUnbiased(pool.length());
                selectedChars.add(pool.charAt(idx));
            }

            // Fill remainder
            int remaining = length - selectedChars.size();
            for (int i = 0; i < remaining; i++) {
                int idx = nextIntUnbiased(poolSize);
                selectedChars.add(combinedPool.charAt(idx));
            }

            // Fisher-Yates shuffle
            for (int i = selectedChars.size() - 1; i > 0; i--) {
                int j = nextIntUnbiased(i + 1);
                Collections.swap(selectedChars, i, j);
            }

            StringBuilder secretBuilder = new StringBuilder();
            for (char c : selectedChars) {
                secretBuilder.append(c);
            }
            String secret = secretBuilder.toString();

            int entropyBits = (int) Math.round(length * (Math.log(poolSize) / Math.log(2)));
            String strengthLevel = calculatePasswordStrength(entropyBits);

            result.put("secret", secret);
            result.put("length", length);
            result.put("poolSize", poolSize);
            result.put("entropyBits", entropyBits);
            result.put("strengthLevel", strengthLevel);
            result.put("mode", "PASSWORD");
            result.put("entropyExplanation", entropyBits + " bits of entropy (character search space). Note: Entropy measures mathematical search-space uncertainty against brute-force attacks; it does not protect against phishing or malware keystroke logging.");

            JSONObject groups = new JSONObject();
            groups.put("hasUppercase", !upper.isEmpty());
            groups.put("hasLowercase", !lower.isEmpty());
            groups.put("hasNumbers", !numbers.isEmpty());
            groups.put("hasSpecial", !special.isEmpty());
            result.put("characterGroups", groups);

        } catch (Exception e) {
            Log.e(TAG, "generatePassword failed", e);
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {}
        }
        return result;
    }

    /**
     * Generates a passphrase using the curated 2,048-word dictionary.
     */
    public JSONObject generatePassphrase(int wordCount, String separator, boolean capitalize, boolean includeNumber) {
        JSONObject result = new JSONObject();
        try {
            int count = Math.max(3, Math.min(10, wordCount));
            String sep = (separator != null) ? separator : "-";

            String[] words = PassphraseWordlist.WORDS;
            int wordlistSize = words.length; // 2048

            List<String> selectedWords = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                int idx = nextIntUnbiased(wordlistSize);
                String word = words[idx];
                if (capitalize && !word.isEmpty()) {
                    word = Character.toUpperCase(word.charAt(0)) + word.substring(1);
                }
                selectedWords.add(word);
            }

            if (includeNumber) {
                int digit = nextIntUnbiased(10);
                int targetWordIdx = nextIntUnbiased(selectedWords.size());
                selectedWords.set(targetWordIdx, selectedWords.get(targetWordIdx) + digit);
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < selectedWords.size(); i++) {
                if (i > 0) sb.append(sep);
                sb.append(selectedWords.get(i));
            }
            String secret = sb.toString();

            // Entropy: count * log2(2048) = count * 11 bits
            double bits = count * (Math.log(wordlistSize) / Math.log(2));
            if (includeNumber) {
                bits += (Math.log(10) / Math.log(2));
            }
            if (capitalize) {
                bits += count;
            }
            int entropyBits = (int) Math.round(bits);
            String strengthLevel = calculatePassphraseStrength(entropyBits);

            result.put("secret", secret);
            result.put("wordCount", count);
            result.put("wordlistSize", wordlistSize);
            result.put("entropyBits", entropyBits);
            result.put("strengthLevel", strengthLevel);
            result.put("mode", "PASSPHRASE");
            result.put("separator", sep);
            result.put("entropyExplanation", entropyBits + " bits of entropy (dictionary search space). Note: Entropy measures mathematical search-space uncertainty against brute-force attacks; it does not protect against phishing or malware keystroke logging.");

        } catch (Exception e) {
            Log.e(TAG, "generatePassphrase failed", e);
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {}
        }
        return result;
    }

    /**
     * Copies secret text to system clipboard with sensitive flag and auto-clear timer.
     */
    public boolean copySensitiveToClipboard(String label, String secretText) {
        try {
            ClipboardManager cm = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm == null) return false;

            ClipData clip = ClipData.newPlainText(label != null ? label : "Password", secretText);

            // API 33+ (Android 13 Tiramisu) sensitive content flag
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                PersistableBundle bundle = new PersistableBundle();
                bundle.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
                clip.getDescription().setExtras(bundle);
            }

            cm.setPrimaryClip(clip);

            // Schedule auto-clear of clipboard after 60 seconds
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        cm.clearPrimaryClip();
                    } else {
                        cm.setPrimaryClip(ClipData.newPlainText("", ""));
                    }
                } catch (Exception ex) {
                    Log.w(TAG, "Clipboard auto-clear failed: " + ex.getMessage());
                }
            }, CLIPBOARD_AUTOCLEAR_DELAY_MS);

            return true;
        } catch (Exception e) {
            Log.e(TAG, "copySensitiveToClipboard error", e);
            return false;
        }
    }

    private String filterChars(String source, boolean avoidSimilar, boolean avoidAmbiguous) {
        StringBuilder sb = new StringBuilder();
        for (char c : source.toCharArray()) {
            if (avoidSimilar && SIMILAR_CHARS.indexOf(c) != -1) {
                continue;
            }
            if (avoidAmbiguous && AMBIGUOUS_SPECIALS.indexOf(c) != -1) {
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private String calculatePasswordStrength(int entropyBits) {
        if (entropyBits < 60) return "WEAK";
        if (entropyBits < 80) return "MEDIUM";
        if (entropyBits < 120) return "STRONG";
        return "VERY_STRONG";
    }

    private String calculatePassphraseStrength(int entropyBits) {
        if (entropyBits < 45) return "WEAK";
        if (entropyBits < 65) return "MEDIUM";
        if (entropyBits < 90) return "STRONG";
        return "VERY_STRONG";
    }
}
