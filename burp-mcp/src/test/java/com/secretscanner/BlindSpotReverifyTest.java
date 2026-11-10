package com.secretscanner;

import burp.api.montoya.logging.Logging;
import org.junit.jupiter.api.Test;

import java.io.PrintStream;
import java.util.List;

/**
 * Ad-hoc re-verification harness (2026-07-28) for the "SS=0" cells in the
 * SecretsSurvive benchmark that contradict SS's demonstrated behaviour.
 *
 * Runs the REAL SecretScanner engine (FULL tier, default config) against
 * faithful reconstructions of the key:value context for each questionable key,
 * under both a real-looking field name and a neutral one, and prints exactly
 * what SS reports (ruleId | severity | keyName | value). Not an assertion test —
 * it emits measured verdicts to stdout for the reconciliation.
 */
class BlindSpotReverifyTest {

    private static final Logging NOOP_LOG = new Logging() {
        @Override public PrintStream output()                              { return System.out; }
        @Override public PrintStream error()                               { return System.err; }
        @Override public void logToOutput(String message)                  {}
        @Override public void logToOutput(Object message)                  {}
        @Override public void logToError(String message)                   {}
        @Override public void logToError(String message, Throwable cause)  {}
        @Override public void logToError(Throwable cause)                  {}
        @Override public void raiseDebugEvent(String message)              {}
        @Override public void raiseInfoEvent(String message)               {}
        @Override public void raiseErrorEvent(String message)              {}
        @Override public void raiseCriticalEvent(String message)           {}
    };

    private static SecretScanner scanner() {
        ScanSettings s = new ScanSettings();
        s.setTier(ScanSettings.ScanTier.FULL);
        s.setPiiEnabled(true);
        return new SecretScanner(s, NOOP_LOG);
    }

    /** One questionable key: gt idx, real field label, and raw value. */
    private record K(String gt, String field, String value) {}

    @Test
    void reverify() {
        K[] keys = new K[] {
            new K("49", "App_Key",            "rJU8Q~KTJQe_QUU8Wo_l" + "cZ0fF-gSmyuPhvWlNa1F"),
            new K("55", "pdfTokenApiApp_Key",  "hGj8Q~1k~ecABgDaevj0" + "qIh~w1lFCp7bg8E8tavz"),
            new K("72", "clientSecret",        "p6x8Q~0IS1zEjObp-MqL" + "YJinWnQvl2LXNMQ.zb5c"),
            new K("68", "auko",                "555db74c0a3a451d86184b383f647735"),
            new K("69", "fnol",                "7e51a524a66b456a933994bb8990b123"),
            new K("70", "policySearch",        "73b9f3093a054dac97cd6d86a58f6154"),
            new K("71", "subscriptionKey",     "e2c08498ba3f4fab82ac67e658f2e235"),
            // slashy len-63 values (tests GENERIC_KV slash-rejection); real semantic field names
            new K("46", "App_ID",  "jxbb9xlQoDVQTbWeXnxYm/b/bt8/YJgh8JSbvZuC2VsVibuWwsGDvKxEwuJE123"),
            new K("47", "App_Key", "PiYwnkupyKE6n7c3znhTgpSdtqKsrZm7/FsuvUtnUNykfPz38uRaF5C3KTQn123"),
            // bare Azure GUIDs under their real field names (tests resource/app-id detection)
            new K("234", "ssrtokenAPIResource", "f31d0e77-4294-4451-bffd-9263351d6097"),
            new K("271", "loginClientId",       "b3d1e51e-c5a7-4372-8c6a-49875de77e83"),
            new K("273", "tokenAPIResource",     "2ee06474-490b-4e89-bc22-c5835249314f"),
            new K("294", "pdfTokenAPIResource",  "d8b6e8ff-7ae2-440b-909f-c442b5a8ed56"),
            new K("295", "pdfTokenApiApp_ID",    "b8e345d2-bb51-42e3-ac99-9bf1dbee4d94"),
            new K("322", "appIdObfuscated",      "fa0748ed-bdb6-4d2f-a24c-c9588fc46d3e"),
            new K("324", "tokenApiApp_ID",       "51699e8f-2abe-42b4-b4f4-6bfe0b3198d3"),
            new K("333", "audience",             "73edeb92-20da-48ba-b9d9-29ae9c5fa933"),
        };

        SecretScanner sc = scanner();
        System.out.println("\n===== SS RE-VERIFY (real engine, FULL tier, default config) =====");
        // Test each value under BOTH its real-looking field name AND a neutral,
        // non-semantic field name ("x9f2c" / obfuscated), so we can tell whether
        // detection is value-driven (robust) or field-name-driven (fragile).
        for (K k : keys) {
            for (String fld : new String[]{ k.field, "x9f2c" }) {
                String body = "var cfg={env:\"uat\",apiVersion:\"2\","
                        + fld + ":\"" + k.value + "\","
                        + "resource:\"cfc27691-5c79-410b-9074-eaacbddeb5df\"};";
                List<SecretFinding> fs = sc.scanText(body, "application/javascript",
                        "https://demo.local/bundles/gt" + k.gt + ".js");
                boolean hit = false;
                StringBuilder sb = new StringBuilder();
                for (SecretFinding f : fs) {
                    if (f.matchedValue() != null && f.matchedValue().contains(k.value.substring(0, 8))) {
                        hit = true;
                        sb.append("\n      -> ").append(f.ruleId()).append(" | ").append(f.severity())
                          .append(" | ").append(f.confidence()).append(" | key=").append(f.keyName());
                    }
                }
                String tag = fld.equals(k.field) ? "realname" : "NEUTRAL ";
                System.out.println("gt" + k.gt + " [" + tag + "] field=" + fld
                        + "  ==> SS " + (hit ? "DETECTS" : "MISSES") + sb);
            }
        }
        System.out.println("===== END RE-VERIFY =====\n");
    }
}
