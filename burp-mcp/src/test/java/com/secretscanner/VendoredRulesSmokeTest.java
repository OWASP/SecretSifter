package com.secretscanner;

import com.secretscanner.core.ValidationRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.PrintStream;
import java.util.List;

import burp.api.montoya.logging.Logging;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end wiring check for the vendored (Kingfisher/Betterleaks) context rules: a crafted token
 * for each sample provider must be detected by its specific KF_* rule through the real scan path
 * (RuleLoader -> keyword prefilter -> SecretScanner), and each KF_* rule must resolve in the
 * validation catalog under its provider. Guards against the import silently breaking.
 */
@DisplayName("Vendored rules — detection + catalog wiring")
class VendoredRulesSmokeTest {

    private static final Logging NOOP = new Logging() {
        public PrintStream output() { return System.out; }
        public PrintStream error()  { return System.err; }
        public void logToOutput(String m) {}
        public void logToOutput(Object m) {}
        public void logToError(String m) {}
        public void logToError(String m, Throwable c) {}
        public void logToError(Throwable c) {}
        public void raiseDebugEvent(String m) {}
        public void raiseInfoEvent(String m) {}
        public void raiseErrorEvent(String m) {}
        public void raiseCriticalEvent(String m) {}
    };

    private static List<SecretFinding> scan(String body) {
        ScanSettings s = new ScanSettings();
        s.setTier(ScanSettings.ScanTier.FULL);
        return new SecretScanner(s, NOOP).scanText(body, "application/javascript",
                "https://app.example.test/static/main.js");
    }

    private static void assertDetected(String ruleId, String body, String value) {
        List<SecretFinding> fs = scan(body);
        assertTrue(fs.stream().anyMatch(f -> f.ruleId().equals(ruleId) && f.matchedValue().equals(value)),
                ruleId + " did not fire on its own token. Findings: " + fs);
        // catalog wiring: the rule must resolve and group under a non-blank provider
        ValidationRule vr = ValidationCatalog.forRuleId(ruleId);
        assertNotNull(vr, ruleId + " missing from validation catalog");
        assertFalse(vr.provider() == null || vr.provider().isBlank(), ruleId + " has no provider");
        assertTrue(ValidationCatalog.byProvider().containsKey(vr.provider()),
                vr.provider() + " not grouped in catalog");
    }

    @Test void assemblyai()  { assertDetected("KF_ASSEMBLYAI_API_KEY",
            "const assemblyai_key = \"0123456789abcdef0123456789abcdef\";", "0123456789abcdef0123456789abcdef"); }

    @Test void deepgram()    { assertDetected("KF_DEEPGRAM_API_KEY",
            "deepgram_api_key: \"0123456789abcdef0123456789abcdef01234567\"", "0123456789abcdef0123456789abcdef01234567"); }

    @Test void elevenlabs()  { assertDetected("KF_ELEVENLABS_API_KEY",
            "elevenlabs = \"sk_0123456789abcdef0123456789abcdef0123456789abcdef\"",
            "sk_0123456789abcdef0123456789abcdef0123456789abcdef"); }

    @Test void mattermost()  { assertDetected("KF_MATTERMOST_ACCESS_TOKEN",
            "mattermost_token = \"abcdefghij0123456789abcdef\"", "abcdefghij0123456789abcdef"); }

    @Test void virustotal()  { assertDetected("KF_VIRUSTOTAL_API_KEY_1",
            "virustotal_api_key = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); }

    @Test void fastly()      { assertDetected("KF_FASTLY_API_TOKEN",
            "fastly_token = \"abcd1234efgh5678ijkl9012mnop3456\"", "abcd1234efgh5678ijkl9012mnop3456"); }

    @Test void catalogCoversVendoredProviders() {
        // a spread of imported providers must now be present in the grouped catalog
        var providers = ValidationCatalog.byProvider().keySet();
        for (String p : List.of("AssemblyAI", "Deepgram", "ElevenLabs", "Mattermost", "Fastly", "Pinecone", "Scaleway"))
            assertTrue(providers.contains(p), "catalog missing imported provider: " + p);
    }
}
