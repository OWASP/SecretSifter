package com.secretscanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AI triage: reply parsing, prompt safety, model choice")
class AiTriageProviderTest {

    private static SecretFinding f(String key, String value, String sev) {
        return SecretFinding.of("GENERIC_KV", "Secret in Key-Value Pair", key, value, sev, "FIRM", 1,
                key + ": \"" + value + "\"", "https://app.example.test/main.js?token=abc");
    }

    @Test void wellFormedReplyIsUsed() {
        List<AiTriageProvider.TriageResult> r = AiTriageProvider.parseBatchJson(
                "Here you go:\n```json\n[{\"id\":1,\"real\":true,\"severity\":\"Critical - live\",\"confidence\":\"CERTAIN\"},"
                + "{\"id\":2,\"real\":false,\"reasoning\":\"placeholder\"}]\n```", 2);
        assertTrue(r.get(0).hasVerdict());
        assertEquals("CRITICAL", r.get(0).severity());
        assertTrue(r.get(1).hasVerdict());
        assertFalse(r.get(1).real());
    }

    @Test void renumberedOrPartialRepliesChangeNothing() {
        for (String bad : List.of(
                "[{\"id\":0,\"real\":true,\"severity\":\"HIGH\"},{\"id\":1,\"real\":true,\"severity\":\"LOW\"}]",   // 0-based
                "[{\"id\":1,\"real\":true,\"severity\":\"HIGH\"}]",                                               // missing id 2
                "[{\"id\":1,\"real\":true,\"severity\":\"HIGH\"},{\"id\":1,\"real\":true,\"severity\":\"LOW\"}]",   // duplicate
                "[{\"id\":1,\"real\":true,\"severity\":\"HIGH\"},{\"id\":2,\"real\":tr",                           // cut off
                "Findings [1] and [2] look real.")) {
            List<AiTriageProvider.TriageResult> r = AiTriageProvider.parseBatchJson(bad, 2);
            assertTrue(r.stream().noneMatch(AiTriageProvider.TriageResult::hasVerdict), bad);
        }
    }

    @Test void unknownSeverityIsNoVerdictNotMedium() {
        List<AiTriageProvider.TriageResult> r = AiTriageProvider.parseBatchJson(
                "[{\"id\":1,\"real\":true,\"severity\":\"serious\"}]", 1);
        assertFalse(r.get(0).hasVerdict());
    }

    @Test void promptsNeverContainTheSecret() {
        String secret = "sk_live_51HxQwErTyUiOpAs" + "DfGhJkLzXcVb1234567890ab";
        SecretFinding finding = f("stripeKey", secret, "HIGH");
        String batch = AiTriageProvider.buildBatchPrompt(List.of(finding));
        String single = AiTriageProvider.buildSinglePrompt(finding);
        assertFalse(batch.contains(secret));
        assertFalse(single.contains(secret));
        assertFalse(batch.contains("token=abc"), "query strings are dropped from URLs");
        assertTrue(batch.contains("untrusted data"));
        assertTrue(batch.contains("[VALUE]"));
    }

    @Test void singleReplyParsing() {
        assertTrue(AiTriageProvider.parseSingleReply("VERDICT: REAL\nSEVERITY: HIGH\nREASON: live key").hasVerdict());
        assertFalse(AiTriageProvider.parseSingleReply("I think it is fine").hasVerdict());
        assertFalse(AiTriageProvider.parseSingleReply("VERDICT: REAL\nSEVERITY: very bad").hasVerdict());
    }

    @Test void deterministicRulesUseWholeWordsAndRespectLowVerdicts() {
        assertEquals("INFORMATION", AiTriageProvider.deterministicSeverity(f("appKeyboardLayout", "x", "LOW"), "INFORMATION"));
        assertEquals("CRITICAL", AiTriageProvider.deterministicSeverity(f("appKey", "x", "HIGH"), "HIGH"));
        assertEquals("LOW", AiTriageProvider.deterministicSeverity(f("appKey", "x", "HIGH"), "LOW"));
        SecretFinding noRule = SecretFinding.of("X", null, "k", "v", "HIGH", "FIRM", 1, "", "u");
        assertEquals("HIGH", AiTriageProvider.deterministicSeverity(noRule, "HIGH"));
    }

    @Test void modelResolution() {
        // no key: no lookup possible, fall back per provider
        assertEquals("claude-opus-5-5", AiTriageProvider.Models.resolve(AiTriageProvider.Provider.ANTHROPIC, "", null, "latest"));
        // an explicit model is used as-is
        assertEquals("claude-sonnet-5-5", AiTriageProvider.Models.resolve(AiTriageProvider.Provider.ANTHROPIC, "", null, "claude-sonnet-5-5"));
        // a model saved for another vendor is ignored
        assertEquals("claude-opus-5-5", AiTriageProvider.Models.resolve(AiTriageProvider.Provider.ANTHROPIC, "", null, "gpt-4o"));
        assertTrue(AiTriageProvider.Models.isFlagshipChat(AiTriageProvider.Provider.OPENAI, "gpt-5"));
        assertFalse(AiTriageProvider.Models.isFlagshipChat(AiTriageProvider.Provider.OPENAI, "gpt-5-mini"));
        assertTrue(AiTriageProvider.Models.versionCompare("gemini-2.5-pro", "gemini-2.0-pro") > 0);
    }

    @Test void endpointsMustBeHttpsUnlessLocal() {
        assertThrows(IllegalArgumentException.class, () -> AiTriageProvider.Models.requireSafeEndpoint("http://llm.example.test/v1/chat/completions"));
        AiTriageProvider.Models.requireSafeEndpoint("http://localhost:11434/v1/chat/completions");
        AiTriageProvider.Models.requireSafeEndpoint("https://api.mistral.ai/v1/chat/completions");
    }
}
