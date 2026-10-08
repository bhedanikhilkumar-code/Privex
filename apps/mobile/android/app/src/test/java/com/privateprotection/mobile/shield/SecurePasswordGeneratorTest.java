package com.privateprotection.mobile.shield;

import android.content.Context;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class SecurePasswordGeneratorTest {

    private Context mockContext;
    private SecurePasswordGenerator generator;

    @Before
    public void setUp() {
        mockContext = Mockito.mock(Context.class);
        when(mockContext.getApplicationContext()).thenReturn(mockContext);
        generator = new SecurePasswordGenerator(mockContext);
    }

    @Test
    public void testNextIntUnbiasedDistributionAndRange() {
        int bound = 10;
        int[] counts = new int[bound];
        for (int i = 0; i < 5000; i++) {
            int val = SecurePasswordGenerator.nextIntUnbiased(bound);
            assertTrue("Value must be >= 0", val >= 0);
            assertTrue("Value must be < bound", val < bound);
            counts[val]++;
        }
        for (int count : counts) {
            assertTrue("Each bucket should be sampled multiple times", count > 300);
        }
    }

    @Test
    public void testGeneratePasswordDefaultPreset() throws Exception {
        JSONObject options = new JSONObject();
        options.put("length", 20);
        options.put("useUppercase", true);
        options.put("useLowercase", true);
        options.put("useNumbers", true);
        options.put("useSpecial", true);

        JSONObject result = generator.generatePassword(options);
        assertNotNull(result);
        assertEquals(20, result.getInt("length"));
        String secret = result.getString("secret");
        assertEquals(20, secret.length());

        assertTrue("Must contain uppercase", secret.matches(".*[A-Z].*"));
        assertTrue("Must contain lowercase", secret.matches(".*[a-z].*"));
        assertTrue("Must contain digit", secret.matches(".*[0-9].*"));
        assertTrue("Must have positive entropy", result.getInt("entropyBits") >= 100);
        assertEquals("PASSWORD", result.getString("mode"));
    }

    @Test
    public void testGeneratePasswordMinAndMaxBounds() throws Exception {
        // Test length clamp to min 12
        JSONObject optionsShort = new JSONObject();
        optionsShort.put("length", 6);
        JSONObject resultShort = generator.generatePassword(optionsShort);
        assertEquals(12, resultShort.getInt("length"));
        assertEquals(12, resultShort.getString("secret").length());

        // Test length clamp to max 128
        JSONObject optionsLong = new JSONObject();
        optionsLong.put("length", 200);
        JSONObject resultLong = generator.generatePassword(optionsLong);
        assertEquals(128, resultLong.getInt("length"));
        assertEquals(128, resultLong.getString("secret").length());
    }

    @Test
    public void testAvoidSimilarAndAmbiguousCharacters() throws Exception {
        JSONObject options = new JSONObject();
        options.put("length", 32);
        options.put("avoidSimilar", true);
        options.put("avoidAmbiguous", true);

        JSONObject result = generator.generatePassword(options);
        String secret = result.getString("secret");

        // Similar: I, O, l, o, 0, 1
        assertFalse("Should not contain 'I'", secret.contains("I"));
        assertFalse("Should not contain 'O'", secret.contains("O"));
        assertFalse("Should not contain 'l'", secret.contains("l"));
        assertFalse("Should not contain 'o'", secret.contains("o"));
        assertFalse("Should not contain '0'", secret.contains("0"));
        assertFalse("Should not contain '1'", secret.contains("1"));

        // Ambiguous: {}[]()/\'"`~,;:.<>
        for (char c : "{}[]()/\\'\"`~,;:.<>".toCharArray()) {
            assertFalse("Should not contain ambiguous char: " + c, secret.indexOf(c) != -1);
        }
    }

    @Test
    public void testGeneratePassphraseBIP39Wordlist() throws Exception {
        JSONObject result = generator.generatePassphrase(5, "-", true, true);
        assertNotNull(result);
        assertEquals(5, result.getInt("wordCount"));
        assertEquals(2048, result.getInt("wordlistSize"));
        assertEquals("PASSPHRASE", result.getString("mode"));
        assertEquals("-", result.getString("separator"));

        String secret = result.getString("secret");
        String[] parts = secret.split("-");
        assertEquals(5, parts.length);

        // Check capitalization on parts
        assertTrue("First character of word should be uppercase", Character.isUpperCase(parts[0].charAt(0)));
        assertTrue("Entropy must reflect dictionary size", result.getInt("entropyBits") >= 55);
    }

    @Test
    public void testPassphraseWordlistIntegrity() {
        assertEquals("Passphrase wordlist must contain exactly 2048 words", 2048, PassphraseWordlist.WORDS.length);
        Set<String> unique = new HashSet<>();
        for (String word : PassphraseWordlist.WORDS) {
            assertNotNull(word);
            assertTrue("Word must not be empty", word.length() > 0);
            unique.add(word);
        }
        assertEquals("All 2048 words must be unique", 2048, unique.size());
    }
}
