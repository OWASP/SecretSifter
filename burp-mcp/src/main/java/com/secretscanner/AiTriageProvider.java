package com.secretscanner;

import com.google.gson.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * AI backend abstraction for finding triage.
 * Implementations: Burp AI, Anthropic API, OpenAI-compatible, Claude via MCP.
 *
 * Flow: AI first validates real vs noise → deterministicSeverity() applies
 * fixed rules for confirmed real findings → noise routed to approval dialog.
 */
public interface AiTriageProvider {

    enum Provider { BURP, ANTHROPIC, OPENAI, MCP }

    record TriageResult(boolean real, String severity, String confidence, String reasoning) {}

    /** Triage a single finding. Blocks. Called from a background thread. */
    TriageResult triage(SecretFinding f) throws Exception;

    /** Triage a batch. Default: sequential single calls. API providers override with true batching. */
    default List<TriageResult> triageBatch(List<SecretFinding> batch) throws Exception {
        List<TriageResult> out = new ArrayList<>();
        for (SecretFinding f : batch) out.add(triage(f));
        return out;
    }

    boolean isAvailable();

    /** True only for McpImpl — lets triageAllWithAi() take the cooperative MCP path. */
    default boolean isMcpProvider() { return false; }

    // ── Deterministic severity (applied after AI confirms real) ─────────────

    static String deterministicSeverity(SecretFinding f, String aiSeverity) {
        String k = f.keyName() == null ? "" : f.keyName().toLowerCase().replaceAll("[_\\-]", "");
        String ruleId = f.ruleId() == null ? "" : f.ruleId().toLowerCase();
        String url    = f.sourceUrl() == null ? "" : f.sourceUrl();
        if (k.startsWith("appkey"))                           return "CRITICAL";
        if (k.startsWith("resourcekey"))                      return "HIGH";
        if (k.startsWith("subscriptionkey"))                  return "HIGH";
        if (k.equals("appid") || k.equals("applicationid"))  return "INFORMATION";
        if ((ruleId.contains("jwt") || f.ruleName().toLowerCase().contains("jwt"))
                && url.contains("[JSON]"))                    return "CRITICAL";
        return normalSev(aiSeverity);
    }

    static String normalSev(String s) {
        if (s == null) return "MEDIUM";
        switch (s.toUpperCase().trim()) {
            case "CRITICAL":               return "CRITICAL";
            case "HIGH":                   return "HIGH";
            case "MEDIUM":                 return "MEDIUM";
            case "LOW":                    return "LOW";
            case "INFORMATION": case "INFO": return "INFORMATION";
            default:                       return "MEDIUM";
        }
    }

    static String normalConf(String c) {
        if (c == null) return "FIRM";
        switch (c.toUpperCase().trim()) {
            case "CERTAIN":   return "CERTAIN";
            case "FIRM":      return "FIRM";
            case "TENTATIVE": return "TENTATIVE";
            default:          return "FIRM";
        }
    }

    // ── Prompt builders ──────────────────────────────────────────────────────

    static String buildSinglePrompt(SecretFinding f) {
        return "You are an expert penetration tester triaging findings from a secret scanner.\n\n" +
               "Finding:\n" +
               "  Rule:          " + nvl(f.ruleName(), "") + " (" + nvl(f.ruleId(), "") + ")\n" +
               "  Key name:      " + nvl(f.keyName(), "") + "\n" +
               "  Matched value: " + nvl(f.matchedValue(), "") + "\n" +
               "  Context line:  " + nvl(f.context(), "") + "\n" +
               "  Source URL:    " + nvl(f.sourceUrl(), "") + "\n" +
               "  Target URL:    " + nvl(f.targetUrl(), "") + "\n\n" +
               "Apply triage rules:\n" +
               "1. VENDOR: Azure AppKey/ClientSecret→CRITICAL; ResourceKey/StorageKey/SubscriptionKey→HIGH; AppId/ClientId/TenantId→INFORMATION\n" +
               "2. JWT: from API/auth endpoint→CRITICAL; from .js→MEDIUM; test payload→LOW\n" +
               "3. PLACEHOLDER: test/example/dummy/placeholder/changeme/12345→FP\n" +
               "4. CONTEXT: code comment→lower severity; disabled block→lower\n" +
               "5. URL: /test/ /dev/ /demo/→lower; .env/config→CRITICAL; API JSON response→HIGH+\n\n" +
               "Reply EXACTLY:\n" +
               "VERDICT: REAL or FP\n" +
               "SEVERITY: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATION\n" +
               "REASON: one sentence";
    }

    static String buildBatchPrompt(List<SecretFinding> findings) {
        StringBuilder sb = new StringBuilder(
            "You are triaging secret detection findings from a web app scanner.\n" +
            "For each finding: is it REAL or FALSE POSITIVE? If real, severity and confidence?\n\n" +
            "Severity: CRITICAL=live prod secrets; HIGH=resource/subscription keys; MEDIUM=internal tokens; LOW=low-impact; INFORMATION=public IDs\n" +
            "FP: placeholder/test/dummy values, UI labels, enum constants, code fragments\n\n" +
            "Return ONLY a JSON array:\n" +
            "[{\"id\":1,\"real\":true,\"severity\":\"HIGH\",\"confidence\":\"FIRM\",\"reasoning\":\"...\"}]\n\n" +
            "FINDINGS:\n");
        JsonArray arr = new JsonArray();
        for (int i = 0; i < findings.size(); i++) {
            SecretFinding f = findings.get(i);
            JsonObject o = new JsonObject();
            o.addProperty("id", i + 1);
            o.addProperty("rule",  nvl(f.ruleId(), nvl(f.ruleName(), "")));
            o.addProperty("key",   nvl(f.keyName(), ""));
            String val = nvl(f.matchedValue(), "");
            o.addProperty("value", val.length() > 40 ? val.substring(0, 37) + "..." : val);
            String ctx = nvl(f.context(), "").replace("\n", " ").strip();
            if (!ctx.isEmpty()) o.addProperty("context", ctx.length() > 80 ? ctx.substring(0, 77) + "..." : ctx);
            String url = nvl(f.sourceUrl(), "");
            if (url.contains("?")) url = url.substring(0, url.indexOf("?")) + "?...";
            o.addProperty("url", url);
            arr.add(o);
        }
        sb.append(arr.toString());
        return sb.toString();
    }

    static List<TriageResult> parseBatchJson(String json, int count) {
        List<TriageResult> out = new ArrayList<>();
        try {
            String t = json.trim();
            int s = t.indexOf('['), e = t.lastIndexOf(']');
            if (s >= 0 && e > s) t = t.substring(s, e + 1);
            JsonArray arr = JsonParser.parseString(t).getAsJsonArray();
            Map<Integer, TriageResult> byId = new LinkedHashMap<>();
            for (JsonElement el : arr) {
                JsonObject o  = el.getAsJsonObject();
                int id        = o.has("id")         ? o.get("id").getAsInt()         : 0;
                boolean real  = !o.has("real")      || o.get("real").getAsBoolean();
                String sev    = o.has("severity")   ? o.get("severity").getAsString()   : "MEDIUM";
                String conf   = o.has("confidence") ? o.get("confidence").getAsString() : "FIRM";
                String reason = o.has("reasoning")  ? o.get("reasoning").getAsString()  : "";
                byId.put(id, new TriageResult(real, normalSev(sev), normalConf(conf), reason));
            }
            for (int i = 1; i <= count; i++)
                out.add(byId.getOrDefault(i, new TriageResult(true, "MEDIUM", "FIRM", "No AI response")));
        } catch (Exception ex) {
            for (int i = 0; i < count; i++)
                out.add(new TriageResult(true, "MEDIUM", "FIRM", "Parse error: " + ex.getMessage()));
        }
        return out;
    }

    static String extractLine(String text, String prefix) {
        if (text == null) return null;
        for (String line : text.split("\n")) {
            line = line.trim();
            if (line.startsWith(prefix)) return line.substring(prefix.length()).trim();
        }
        return null;
    }

    static String nvl(String v, String fb) { return v != null ? v : fb; }

    // ── Factory ──────────────────────────────────────────────────────────────

    static AiTriageProvider forSettings(ScanSettings s, burp.api.montoya.MontoyaApi api) {
        return forSettings(s, api, null);
    }

    static AiTriageProvider forSettings(ScanSettings s, burp.api.montoya.MontoyaApi api, McpBridge mcp) {
        switch (s.getAiProvider()) {
            case BURP:      return new BurpAiImpl(api);
            case ANTHROPIC: return new AnthropicImpl(s.getAiApiKey());
            case OPENAI:    return new OpenAiImpl(s.getAiApiKey(), s.getAiEndpoint(), s.getAiModel());
            case MCP:       return mcp != null ? new McpImpl(mcp) : new BurpAiImpl(api);
            default:        return new BurpAiImpl(api);
        }
    }

    // ── Burp AI ──────────────────────────────────────────────────────────────

    class BurpAiImpl implements AiTriageProvider {
        private final burp.api.montoya.MontoyaApi api;
        BurpAiImpl(burp.api.montoya.MontoyaApi api) { this.api = api; }

        @Override public boolean isAvailable() {
            try { return api.ai().isEnabled(); } catch (Exception e) { return false; }
        }

        @Override public TriageResult triage(SecretFinding f) throws Exception {
            String resp = api.ai().prompt().execute(buildSinglePrompt(f)).content().trim();
            String verdict  = extractLine(resp, "VERDICT:");
            String severity = extractLine(resp, "SEVERITY:");
            String reason   = extractLine(resp, "REASON:");
            boolean real = !"FP".equalsIgnoreCase(verdict) && !"FALSE POSITIVE".equalsIgnoreCase(verdict);
            return new TriageResult(real, normalSev(severity), real ? "CERTAIN" : "TENTATIVE", nvl(reason, ""));
        }
    }

    // ── Anthropic API ────────────────────────────────────────────────────────

    class AnthropicImpl implements AiTriageProvider {
        private static final String ENDPOINT = "https://api.anthropic.com/v1/messages";
        private final String key;
        private final java.net.http.HttpClient http;

        AnthropicImpl(String key) {
            this.key  = key;
            this.http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(30)).build();
        }

        @Override public boolean isAvailable() { return key != null && !key.isBlank(); }

        @Override public TriageResult triage(SecretFinding f) throws Exception {
            return triageBatch(Collections.singletonList(f)).get(0);
        }

        @Override public List<TriageResult> triageBatch(List<SecretFinding> batch) throws Exception {
            JsonObject body = new JsonObject();
            body.addProperty("model", "claude-opus-4-7");
            body.addProperty("max_tokens", 2048);
            JsonArray msgs = new JsonArray();
            JsonObject msg = new JsonObject();
            msg.addProperty("role", "user");
            msg.addProperty("content", buildBatchPrompt(batch));
            msgs.add(msg);
            body.add("messages", msgs);
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(ENDPOINT))
                    .header("Content-Type", "application/json")
                    .header("x-api-key", key)
                    .header("anthropic-version", "2023-06-01")
                    .timeout(Duration.ofSeconds(90))
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .build();
            java.net.http.HttpResponse<String> resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                throw new Exception("Anthropic " + resp.statusCode() + ": " + resp.body().substring(0, Math.min(200, resp.body().length())));
            JsonObject obj = JsonParser.parseString(resp.body()).getAsJsonObject();
            String content = obj.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString();
            return parseBatchJson(content, batch.size());
        }
    }

    // ── OpenAI-compatible ────────────────────────────────────────────────────

    class OpenAiImpl implements AiTriageProvider {
        private static final String DEFAULT_URL = "https://api.openai.com/v1/chat/completions";
        private final String key, endpoint, model;
        private final java.net.http.HttpClient http;

        OpenAiImpl(String key, String endpoint, String model) {
            this.key      = key;
            this.endpoint = (endpoint == null || endpoint.isBlank()) ? DEFAULT_URL : endpoint;
            this.model    = (model    == null || model.isBlank())    ? "gpt-4o"    : model;
            this.http     = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(30)).build();
        }

        @Override public boolean isAvailable() { return key != null && !key.isBlank(); }

        @Override public TriageResult triage(SecretFinding f) throws Exception {
            return triageBatch(Collections.singletonList(f)).get(0);
        }

        @Override public List<TriageResult> triageBatch(List<SecretFinding> batch) throws Exception {
            JsonObject body = new JsonObject();
            body.addProperty("model", model);
            JsonArray msgs = new JsonArray();
            JsonObject msg = new JsonObject();
            msg.addProperty("role", "user");
            msg.addProperty("content", buildBatchPrompt(batch));
            msgs.add(msg);
            body.add("messages", msgs);
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + key)
                    .timeout(Duration.ofSeconds(90))
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .build();
            java.net.http.HttpResponse<String> resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                throw new Exception("OpenAI " + resp.statusCode() + ": " + resp.body().substring(0, Math.min(200, resp.body().length())));
            JsonObject obj = JsonParser.parseString(resp.body()).getAsJsonObject();
            String content = obj.getAsJsonArray("choices").get(0).getAsJsonObject()
                    .getAsJsonObject("message").get("content").getAsString();
            return parseBatchJson(content, batch.size());
        }
    }

    // ── Claude via MCP (cooperative) ─────────────────────────────────────────

    class McpImpl implements AiTriageProvider {
        private final McpBridge bridge;
        McpImpl(McpBridge bridge) { this.bridge = bridge; }

        @Override public boolean isAvailable()    { return bridge != null; }
        @Override public boolean isMcpProvider()  { return true; }

        @Override public TriageResult triage(SecretFinding f) throws Exception {
            throw new UnsupportedOperationException("MCP provider is batch-only via triageAllWithAi()");
        }

        public CompletableFuture<List<TriageResult>> enqueueBatch(List<SecretFinding> findings) {
            return bridge.enqueueTriage(findings);
        }
    }
}
