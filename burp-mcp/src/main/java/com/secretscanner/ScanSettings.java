package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Thread-safe settings model.
 *
 * Primitive fields use volatile for visibility across threads.
 * The CDN blocklist is protected by synchronized methods.
 * Persistence keys are prefixed with "ss." to avoid collisions.
 */
public class ScanSettings {

    public enum ScanTier { FAST, LIGHT, FULL }

    /** Largest response body scanned; bigger bodies are skipped (and logged) to bound memory. */
    public static final int MAX_SCAN_BYTES = 20 * 1024 * 1024;

    /**
     * True for binary media types that cannot carry text secrets (images other than SVG,
     * video, audio, fonts). Their bodies are not scanned.
     */
    public static boolean isBinaryMedia(String contentType) {
        if (contentType == null) return false;
        String ct = contentType.toLowerCase(java.util.Locale.ROOT).trim();
        if (ct.startsWith("image/")) return !ct.startsWith("image/svg");
        return ct.startsWith("video/") || ct.startsWith("audio/") || ct.startsWith("font/")
                || ct.startsWith("application/font-") || ct.startsWith("application/x-font-");
    }

    // ---- preference keys ----
    private static final String KEY_ENABLED        = "ss.enabled";
    private static final String KEY_TIER           = "ss.tier";
    private static final String KEY_ENTROPY        = "ss.entropy";        // stored as String
    private static final String KEY_PII            = "ss.pii";
    private static final String KEY_CDNLIST        = "ss.cdnlist";        // newline-separated
    private static final String KEY_CDN_DEFAULTS_SEEN = "ss.cdnlist.defaultsSeen"; // defaults known at last save

    /** Built-in CDN defaults, so a save can record which ones the user has seen. */
    private static final List<String> CDN_DEFAULTS = List.copyOf(new ScanSettings().cdnBlocklist);

    /** Old bare-label entries that never matched a host, mapped to real domains ("" = drop). */
    private static final java.util.Map<String, String> LEGACY_CDN_ENTRIES = java.util.Map.of(
            "cdnjs", "cdnjs.cloudflare.com", "jsdelivr", "jsdelivr.net", "unpkg", "unpkg.com",
            "stackpath", "bootstrapcdn.com", "maxcdn", "bootstrapcdn.com", "doubleclick", "doubleclick.net",
            "firebase", "");
    private static final String KEY_SCAN_REQUESTS  = "ss.scan_requests";  // scan req headers/body
    private static final String KEY_KEY_BLOCKLIST  = "ss.keyblocklist";   // newline-separated key name suppression list
    private static final String KEY_KEY_ALLOWLIST  = "ss.keyallowlist";   // newline-separated key name force-include list
    private static final String KEY_ALLOW_INSECURE_SSL   = "ss.allow_insecure_ssl";
    private static final String KEY_CUSTOM_RULES         = "ss.customrules";        // newline-separated rule lines
    private static final String KEY_CUSTOM_RULES_ENABLED = "ss.customrules_enabled";
    private static final String KEY_CUSTOM_RULES_ONLY    = "ss.customrules_only";   // raw mode: skip built-in scanners + FP gates
    private static final String KEY_VALIDATION_ENABLED = "ss.validation_enabled";
    private static final String KEY_LIVE_VALIDATION    = "ss.live_validation_enabled";  // master network opt-in (off by default)
    private static final String KEY_VALIDATION_IDS     = "ss.validation_ids";        // newline-separated catalog ids
    private static final String KEY_VALIDATION_IDS_SET = "ss.validation_ids_set";    // "1" once the user has saved a selection
    private static final String KEY_VALIDATION_CUSTOM  = "ss.validation_custom";     // newline-separated custom rule lines
    private static final String KEY_VALIDATION_BASEURLS = "ss.validation_baseurls";  // newline-separated "provider = https://host" lines
    private static final String KEY_MCP_ENABLED          = "ss.mcp_enabled";
    private static final String KEY_AI_PROVIDER  = "ss.ai_provider";
    private static final String KEY_AI_API_KEY   = "ss.ai_api_key";
    private static final String KEY_AI_ENDPOINT  = "ss.ai_endpoint";
    private static final String KEY_AI_MODEL     = "ss.ai_model";

    // ---- fields ----
    private volatile boolean   enabled              = true;
    private volatile ScanTier  tier                 = ScanTier.FULL;
    private volatile double    entropyThreshold     = 3.5;
    private volatile boolean   piiEnabled           = true;
    private volatile boolean   scanRequestsEnabled  = true;
    private volatile boolean   allowInsecureSsl     = false;
    private volatile boolean   customRulesEnabled   = true;
    // Raw mode: when true, the proxy and bulk-scan paths run ONLY user-supplied custom rules
    // and bypass the FP gates (isProbableSecretValue, placeholder check, webpack-hash filter).
    // Allowlist/blocklist/CDN blocklist still apply. Burp's audit (SecretScanCheck) is unaffected.
    private volatile boolean   customRulesOnly      = false;
    private volatile boolean validationEnabled = false;
    private volatile boolean liveValidationEnabled = false;   // network validation: off until the operator opts in
    private final java.util.Set<String> validationEnabledIds = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile boolean validationIdsInitialised = false;
    private final List<String> validationCustomRules = new ArrayList<>();
    private final List<String> validationBaseUrls = new ArrayList<>();   // "provider = https://host" lines (self-hosted overrides)
    private volatile boolean   mcpEnabled           = false;
    private volatile AiTriageProvider.Provider aiProvider  = AiTriageProvider.Provider.BURP;
    private volatile String                    aiApiKey    = "";
    private volatile String                    aiEndpoint  = "";
    private volatile String                    aiModel     = "";

    // Key name blocklist — findings whose matched key name contains any entry are suppressed.
    // Defaults cover common app storage-key constants that are never credentials.
    private final List<String> keyBlocklist = new ArrayList<>(Arrays.asList(
            "STORAGE_KEY_", "storage_key_",
            "STATE_KEY_",   "state_key_",
            "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
    ));

    // Key name allowlist — findings whose matched key name contains any entry are always reported,
    // bypassing isProbableSecretValue() checks. Empty by default; users populate per engagement.
    private final List<String> keyAllowlist = new ArrayList<>();

    // Custom rules — user-defined patterns layered on top of built-ins.
    // Each entry is a raw rule line: "RuleName | regex | severity"
    // Parsed at scan time by SecretScanner. Empty by default.
    private final List<String> customRules = new ArrayList<>();

    private final List<String> cdnBlocklist = new ArrayList<>(Arrays.asList(
            // JS/CSS CDNs — static asset delivery, no secrets expected
            "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "ajax.googleapis.com",
            "ajax.microsoft.com", "code.jquery.com", "bootstrapcdn.com", "ajax.aspnetcdn.com",
            "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com", "polyfill.io",
            // Analytics / tracking — no secrets, just noise
            "segment.com", "segment.io", "doubleclick.net",
            "cdn.amplitude.com", "cdn.mxpnl.com", "cdn.heapanalytics.com", "cdn.optimizely.com",
            "googletagmanager.com", "hotjar.com",
            "cloudflareinsights.com", "cdn.cookielaw.org",
            "dc.services.visualstudio.com",
            "launchdarkly.com", "data.microsoft.com",
            "rs.fullstory.com", "edge.fullstory.com",
            "sentry.io", "bat.bing.com", "snap.licdn.com",
            "platform.linkedin.com", "connect.facebook.net",
            "static.klaviyo.com", "static.ads-twitter.com",
            // NOTE: amazonaws.com and cloudfront.net intentionally excluded —
            // AWS API Gateway + CloudFront are used to serve real API responses.
            // Add them manually here if you want to skip those hosts.
            "akamaiedge.net",
            // Device fingerprinting / bot-detection CDNs — no app secrets, lots of noise
            "online-metrix.net",        // ThreatMetrix / LexisNexis Risk Solutions
            // SSO / identity providers — these are third-party auth pages, not app assets
            "microsoftonline.com",      // Microsoft Entra / Azure AD login
            "msauth.net",               // Microsoft auth CDN (aadcdn.msauth.net etc.)
            "msftauth.net",             // Microsoft alt auth domain
            "live.com",                 // Microsoft Live login
            // Adobe marketing cloud — DTM/Launch tag managers and analytics CDNs
            "adobedtm.com",             // Adobe DTM / Launch (assets.adobedtm.com etc.)
            "omtrdc.net",               // Adobe Analytics / Target
            "demdex.net",               // Adobe Audience Manager
            // General analytics / RUM CDNs
            "google-analytics.com",
            "nr-data.net",              // New Relic browser agent
            // Customer experience / feedback analytics
            "medallia.com",             // Medallia digital experience (analytics-fe.*)
            "medallia.eu"               // Medallia EU data-residency endpoint
    ));

    // =========================================================================
    // Getters / setters
    // =========================================================================

    public boolean isEnabled()                   { return enabled; }
    public void    setEnabled(boolean b)         { enabled = b; }

    public ScanTier getTier()                    { return tier; }
    public void     setTier(ScanTier t)          { if (t != null) tier = t; }

    public double getEntropyThreshold()          { return entropyThreshold; }
    public void   setEntropyThreshold(double t)  { entropyThreshold = t; }

    public boolean isPiiEnabled()                        { return piiEnabled; }
    public void    setPiiEnabled(boolean b)              { piiEnabled = b; }

    public boolean isScanRequestsEnabled()               { return scanRequestsEnabled; }
    public void    setScanRequestsEnabled(boolean b)     { scanRequestsEnabled = b; }

    public boolean isAllowInsecureSsl()                  { return allowInsecureSsl; }
    public void    setAllowInsecureSsl(boolean b)        { allowInsecureSsl = b; }

    public boolean isCustomRulesEnabled()                { return customRulesEnabled; }
    public void    setCustomRulesEnabled(boolean b)      { customRulesEnabled = b; }
    public boolean isCustomRulesOnly()                   { return customRulesOnly; }
    public void    setCustomRulesOnly(boolean b)         { customRulesOnly = b; }

    public boolean isValidationEnabled()                 { return validationEnabled; }
    public void    setValidationEnabled(boolean b)       { validationEnabled = b; }
    public boolean isLiveValidationEnabled()             { return liveValidationEnabled; }
    public void    setLiveValidationEnabled(boolean b)   { liveValidationEnabled = b; }

    /**
     * Selected catalog ids; until the user saves a selection, defaults to ALL catalog entries so that
     * turning the Validate toggle on checks everything applicable. Offline checks (JWT expiry, Luhn)
     * run immediately; live/network checks still run only when the separate "Allow live (network)
     * validation" switch is on, so defaulting them selected never contacts anything on its own.
     */
    public java.util.Set<String> getValidationEnabledIds() {
        if (validationIdsInitialised) return java.util.Set.copyOf(validationEnabledIds);
        java.util.Set<String> def = new java.util.HashSet<>();
        for (com.secretscanner.core.ValidationRule vr : ValidationCatalog.builtIn())
            def.add(vr.id());
        return def;
    }
    public void setValidationEnabledIds(java.util.Collection<String> ids) {
        validationEnabledIds.clear();
        if (ids != null) validationEnabledIds.addAll(ids);
        validationIdsInitialised = true;
    }
    public List<String> getValidationCustomRules()       { return new ArrayList<>(validationCustomRules); }
    public void setValidationCustomRules(java.util.Collection<String> lines) {
        validationCustomRules.clear();
        if (lines != null) for (String l : lines) if (l != null && !l.isBlank()) validationCustomRules.add(l);
    }

    /** Self-hosted base-URL overrides, as raw "provider = https://host" lines. */
    public List<String> getValidationBaseUrls()          { return new ArrayList<>(validationBaseUrls); }
    public void setValidationBaseUrls(java.util.Collection<String> lines) {
        validationBaseUrls.clear();
        if (lines != null) for (String l : lines) if (l != null && !l.isBlank()) validationBaseUrls.add(l);
    }
    /** Parsed provider → base-URL map from the override lines (case-insensitive provider key). */
    public java.util.Map<String, String> validationBaseUrlMap() {
        java.util.Map<String, String> m = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String l : validationBaseUrls) {
            int eq = l.indexOf('=');
            if (eq <= 0) continue;
            String prov = l.substring(0, eq).trim();
            String url  = l.substring(eq + 1).trim();
            if (!prov.isEmpty() && !url.isEmpty()) m.put(prov, url);
        }
        return m;
    }

    public boolean isMcpEnabled()                        { return mcpEnabled; }
    public void    setMcpEnabled(boolean b)              { mcpEnabled = b; }

    public AiTriageProvider.Provider getAiProvider()               { return aiProvider; }
    public void setAiProvider(AiTriageProvider.Provider p)         { if (p != null) aiProvider = p; }
    public String getAiApiKey()                                    { return aiApiKey; }
    public void   setAiApiKey(String k)                            { aiApiKey  = k != null ? k : ""; }
    public String getAiEndpoint()                                  { return aiEndpoint; }
    public void   setAiEndpoint(String e)                          { aiEndpoint = e != null ? e : ""; }
    public String getAiModel()                                     { return aiModel; }
    public void   setAiModel(String m)                             { aiModel   = m != null ? m : ""; }

    public synchronized List<String> getCdnBlocklist() {
        return new ArrayList<>(cdnBlocklist);
    }

    public synchronized void setCdnBlocklist(List<String> list) {
        cdnBlocklist.clear();
        if (list != null) cdnBlocklist.addAll(list);
    }

    public synchronized List<String> getKeyBlocklist() {
        return new ArrayList<>(keyBlocklist);
    }

    public synchronized void setKeyBlocklist(List<String> list) {
        keyBlocklist.clear();
        if (list != null) keyBlocklist.addAll(list);
    }

    /** Returns true if the key name contains any entry in the key blocklist (case-insensitive). */
    public synchronized boolean isKeyBlocked(String keyName) {
        if (keyName == null || keyName.isBlank()) return false;
        String kl = keyName.toLowerCase();
        // Framework "public" env prefixes (NEXT_PUBLIC_, VITE_PUBLIC_ ...) mark values the build
        // ships to the browser on purpose. A secret-named key under such a prefix
        // (NEXT_PUBLIC_STRIPE_SECRET_KEY, NEXT_PUBLIC_DB_PASSWORD) is a mistake worth reporting.
        boolean secretNamed = kl.contains("secret") || kl.contains("password") || kl.contains("passwd")
                || kl.contains("private") || kl.contains("service_role") || kl.contains("servicerole");
        for (String entry : keyBlocklist) {
            if (entry.isBlank()) continue;
            String e = entry.toLowerCase();
            if (!kl.contains(e)) continue;
            if (secretNamed && e.endsWith("public_")) continue;
            return true;
        }
        return false;
    }

    public synchronized List<String> getKeyAllowlist() {
        return new ArrayList<>(keyAllowlist);
    }

    public synchronized void setKeyAllowlist(List<String> list) {
        keyAllowlist.clear();
        if (list != null) keyAllowlist.addAll(list);
    }

    public synchronized List<String> getCustomRules() {
        return new ArrayList<>(customRules);
    }

    public synchronized void setCustomRules(List<String> list) {
        customRules.clear();
        if (list != null) customRules.addAll(list);
    }

    /** Returns true if the key name contains any entry in the key allowlist (case-insensitive). */
    public synchronized boolean isKeyAllowlisted(String keyName) {
        if (keyName == null || keyAllowlist.isEmpty()) return false;
        String kl = keyName.toLowerCase();
        for (String entry : keyAllowlist) {
            if (!entry.isBlank() && kl.contains(entry.toLowerCase())) return true;
        }
        return false;
    }

    /**
     * Returns true if the given URL's hostname matches any entry in the CDN blocklist,
     * or if the hostname itself contains the word "cdn".
     *
     * The check is applied to the HOSTNAME only, not the full URL string, to avoid
     * false-positive CDN blocks for in-scope JS files whose path or filename happens
     * to contain a blocklist word (e.g., /js/firebase-init.js, /assets/cdn-config/app.js).
     */
    public boolean isExternalCdn(String urlOrHost) {
        if (urlOrHost == null || urlOrHost.isBlank()) return false;
        // Extract hostname when a full URL is passed; fall back to the raw value otherwise.
        String host;
        if (urlOrHost.startsWith("http://") || urlOrHost.startsWith("https://")) {
            try {
                host = new java.net.URL(urlOrHost).getHost().toLowerCase();
            } catch (Exception e) {
                host = urlOrHost.toLowerCase();
            }
        } else {
            host = urlOrHost.toLowerCase();
        }
        // No blanket "cdn.*" rule: first-party asset hosts (cdn.<company>.com) carry the
        // application's own bundles. Third-party CDNs are listed by domain in cdnBlocklist.
        synchronized (this) {
            for (String entry : cdnBlocklist) {
                // Domain-suffix match: entry "segment.com" blocks cdn.segment.com,
                // abn.segment.com, analytics.segment.com but NOT api.mysegment.com
                String e = entry.toLowerCase();
                if (host.equals(e) || host.endsWith("." + e)) return true;
            }
        }
        return false;
    }

    // =========================================================================
    // Persistence
    // =========================================================================

    /** Convenience overload — accepts a Preferences object directly (used by McpBridge). */
    public void saveToPreferences(Preferences prefs) {
        try {
            prefs.setBoolean(KEY_ENABLED,              enabled);
            prefs.setString(KEY_TIER,                  tier.name());
            prefs.setString(KEY_ENTROPY,               String.valueOf(entropyThreshold));
            prefs.setBoolean(KEY_PII,                  piiEnabled);
            prefs.setBoolean(KEY_SCAN_REQUESTS,        scanRequestsEnabled);
            prefs.setBoolean(KEY_ALLOW_INSECURE_SSL,   allowInsecureSsl);
            prefs.setString(KEY_CDNLIST,               String.join("\n", getCdnBlocklist()));
            prefs.setString(KEY_CDN_DEFAULTS_SEEN,     String.join("\n", CDN_DEFAULTS));
            prefs.setString(KEY_KEY_BLOCKLIST,         String.join("\n", getKeyBlocklist()));
            prefs.setString(KEY_KEY_ALLOWLIST,         String.join("\n", getKeyAllowlist()));
            prefs.setString(KEY_CUSTOM_RULES,          String.join("\n", getCustomRules()));
            prefs.setBoolean(KEY_CUSTOM_RULES_ENABLED, customRulesEnabled);
            prefs.setBoolean(KEY_CUSTOM_RULES_ONLY,    customRulesOnly);
            prefs.setBoolean(KEY_VALIDATION_ENABLED,    validationEnabled);
            prefs.setBoolean(KEY_LIVE_VALIDATION,       liveValidationEnabled);
            prefs.setString(KEY_VALIDATION_IDS,         String.join("\n", getValidationEnabledIds()));
            prefs.setBoolean(KEY_VALIDATION_IDS_SET,    validationIdsInitialised);
            prefs.setString(KEY_VALIDATION_CUSTOM,      String.join("\n", validationCustomRules));
            prefs.setString(KEY_VALIDATION_BASEURLS,    String.join("\n", validationBaseUrls));
            prefs.setBoolean(KEY_MCP_ENABLED,          mcpEnabled);
            prefs.setString(KEY_AI_PROVIDER,           aiProvider.name());
            prefs.setString(KEY_AI_API_KEY,            aiApiKey);
            prefs.setString(KEY_AI_ENDPOINT,           aiEndpoint);
            prefs.setString(KEY_AI_MODEL,              aiModel);
        } catch (Exception ignored) {}
    }

    public void saveToPreferences(MontoyaApi api) {
        try {
            Preferences prefs = api.persistence().preferences();
            prefs.setBoolean(KEY_ENABLED,         enabled);
            prefs.setString(KEY_TIER,             tier.name());
            prefs.setString(KEY_ENTROPY,          String.valueOf(entropyThreshold));
            prefs.setBoolean(KEY_PII,             piiEnabled);
            prefs.setBoolean(KEY_SCAN_REQUESTS,       scanRequestsEnabled);
            prefs.setBoolean(KEY_ALLOW_INSECURE_SSL,  allowInsecureSsl);
            prefs.setString(KEY_CDNLIST,              String.join("\n", getCdnBlocklist()));
            prefs.setString(KEY_CDN_DEFAULTS_SEEN,    String.join("\n", CDN_DEFAULTS));
            prefs.setString(KEY_KEY_BLOCKLIST,    String.join("\n", getKeyBlocklist()));
            prefs.setString(KEY_KEY_ALLOWLIST,    String.join("\n", getKeyAllowlist()));
            prefs.setString(KEY_CUSTOM_RULES,         String.join("\n", getCustomRules()));
            prefs.setBoolean(KEY_CUSTOM_RULES_ENABLED, customRulesEnabled);
            prefs.setBoolean(KEY_CUSTOM_RULES_ONLY,    customRulesOnly);
            prefs.setBoolean(KEY_VALIDATION_ENABLED,    validationEnabled);
            prefs.setBoolean(KEY_LIVE_VALIDATION,       liveValidationEnabled);
            prefs.setString(KEY_VALIDATION_IDS,         String.join("\n", getValidationEnabledIds()));
            prefs.setBoolean(KEY_VALIDATION_IDS_SET,    validationIdsInitialised);
            prefs.setString(KEY_VALIDATION_CUSTOM,      String.join("\n", validationCustomRules));
            prefs.setString(KEY_VALIDATION_BASEURLS,    String.join("\n", validationBaseUrls));
            prefs.setBoolean(KEY_MCP_ENABLED,          mcpEnabled);
            prefs.setString(KEY_AI_PROVIDER,           aiProvider.name());
            prefs.setString(KEY_AI_API_KEY,            aiApiKey);
            prefs.setString(KEY_AI_ENDPOINT,           aiEndpoint);
            prefs.setString(KEY_AI_MODEL,              aiModel);
        } catch (Exception ignored) {
            // Preferences not critical — continue silently
        }
    }

    public void loadFromPreferences(MontoyaApi api) {
        try {
            Preferences prefs = api.persistence().preferences();

            Boolean en = prefs.getBoolean(KEY_ENABLED);
            if (en != null) enabled = en;

            String tierStr = prefs.getString(KEY_TIER);
            if (tierStr != null) {
                try { tier = ScanTier.valueOf(tierStr); } catch (IllegalArgumentException ignored) {}
            }

            String entropyStr = prefs.getString(KEY_ENTROPY);
            if (entropyStr != null) {
                try { entropyThreshold = Double.parseDouble(entropyStr); } catch (NumberFormatException ignored) {}
            }

            Boolean pii = prefs.getBoolean(KEY_PII);
            if (pii != null) piiEnabled = pii;

            Boolean scanReqs = prefs.getBoolean(KEY_SCAN_REQUESTS);
            if (scanReqs != null) scanRequestsEnabled = scanReqs;

            Boolean insecureSsl = prefs.getBoolean(KEY_ALLOW_INSECURE_SSL);
            if (insecureSsl != null) allowInsecureSsl = insecureSsl;

            String cdnStr = prefs.getString(KEY_CDNLIST);
            if (cdnStr != null && !cdnStr.isBlank()) {
                List<String> defaults = getCdnBlocklist();
                java.util.LinkedHashSet<String> merged = new java.util.LinkedHashSet<>();
                for (String line : cdnStr.split("\n")) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) continue;
                    String fixed = LEGACY_CDN_ENTRIES.getOrDefault(trimmed.toLowerCase(java.util.Locale.ROOT), trimmed);
                    if (!fixed.isEmpty()) merged.add(fixed);
                }
                // Add only defaults this user has never seen (introduced by a newer JAR); defaults
                // the user deliberately removed stay removed.
                String seenStr = prefs.getString(KEY_CDN_DEFAULTS_SEEN);
                java.util.Set<String> seen = new java.util.HashSet<>();
                if (seenStr != null) {
                    for (String l : seenStr.split("\n")) if (!l.isBlank()) seen.add(l.trim());
                } else {
                    seen.addAll(merged);                  // first load after upgrade: keep the user's list
                }
                for (String d : defaults) if (!seen.contains(d)) merged.add(d);
                setCdnBlocklist(new ArrayList<>(merged));
            }

            String keyBlockStr = prefs.getString(KEY_KEY_BLOCKLIST);
            if (keyBlockStr != null && !keyBlockStr.isBlank()) {
                List<String> loaded = new ArrayList<>();
                for (String line : keyBlockStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setKeyBlocklist(loaded);
            }

            String keyAllowStr = prefs.getString(KEY_KEY_ALLOWLIST);
            if (keyAllowStr != null) {
                List<String> loaded = new ArrayList<>();
                for (String line : keyAllowStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setKeyAllowlist(loaded);
            }

            Boolean customRulesEn = prefs.getBoolean(KEY_CUSTOM_RULES_ENABLED);
            if (customRulesEn != null) customRulesEnabled = customRulesEn;

            Boolean customRulesOnlyEn = prefs.getBoolean(KEY_CUSTOM_RULES_ONLY);
            if (customRulesOnlyEn != null) customRulesOnly = customRulesOnlyEn;

            Boolean valEn = prefs.getBoolean(KEY_VALIDATION_ENABLED);
            if (valEn != null) validationEnabled = valEn;
            Boolean liveEn = prefs.getBoolean(KEY_LIVE_VALIDATION);
            if (liveEn != null) liveValidationEnabled = liveEn;
            Boolean valSet = prefs.getBoolean(KEY_VALIDATION_IDS_SET);
            if (Boolean.TRUE.equals(valSet)) {
                String ids = prefs.getString(KEY_VALIDATION_IDS);
                java.util.Set<String> set = new java.util.HashSet<>();
                if (ids != null) for (String s2 : ids.split("\n")) if (!s2.isBlank()) set.add(s2.trim());
                setValidationEnabledIds(set);
            }
            String valCustom = prefs.getString(KEY_VALIDATION_CUSTOM);
            if (valCustom != null) {
                java.util.List<String> lines = new java.util.ArrayList<>();
                for (String s2 : valCustom.split("\n")) if (!s2.isBlank()) lines.add(s2);
                setValidationCustomRules(lines);
            }
            String valBaseUrls = prefs.getString(KEY_VALIDATION_BASEURLS);
            if (valBaseUrls != null) {
                java.util.List<String> lines = new java.util.ArrayList<>();
                for (String s2 : valBaseUrls.split("\n")) if (!s2.isBlank()) lines.add(s2);
                setValidationBaseUrls(lines);
            }

            Boolean mcpEn = prefs.getBoolean(KEY_MCP_ENABLED);
            if (mcpEn != null) mcpEnabled = mcpEn;

            String aiProv = prefs.getString(KEY_AI_PROVIDER);
            if (aiProv != null) { try { aiProvider = AiTriageProvider.Provider.valueOf(aiProv); } catch (Exception ignored) {} }
            String aiKey = prefs.getString(KEY_AI_API_KEY);   if (aiKey != null) aiApiKey  = aiKey;
            String aiEp  = prefs.getString(KEY_AI_ENDPOINT);  if (aiEp  != null) aiEndpoint = aiEp;
            String aiMod = prefs.getString(KEY_AI_MODEL);     if (aiMod != null) aiModel    = aiMod;

            String customRulesStr = prefs.getString(KEY_CUSTOM_RULES);
            if (customRulesStr != null && !customRulesStr.isBlank()) {
                List<String> loaded = new ArrayList<>();
                for (String line : customRulesStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setCustomRules(loaded);
            }

        } catch (Exception ignored) {}
    }

    public void resetToDefaults() {
        enabled              = true;
        tier                 = ScanTier.FULL;
        entropyThreshold     = 3.5;
        piiEnabled           = true;
        scanRequestsEnabled  = true;
        allowInsecureSsl     = false;
        customRulesEnabled   = true;
        customRulesOnly      = false;
        mcpEnabled           = false;
        aiProvider           = AiTriageProvider.Provider.BURP;
        aiApiKey             = "";
        aiEndpoint           = "";
        aiModel              = "";
        synchronized (this) {
            keyBlocklist.clear();
            keyBlocklist.addAll(Arrays.asList(
                    "STORAGE_KEY_", "storage_key_",
                    "STATE_KEY_",   "state_key_",
                    "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
            ));
            keyAllowlist.clear();
            customRules.clear();
            validationEnabled = false;
            liveValidationEnabled = false;
            validationEnabledIds.clear();
            validationIdsInitialised = false;
            validationCustomRules.clear();
            validationBaseUrls.clear();
            cdnBlocklist.clear();
            cdnBlocklist.addAll(Arrays.asList(
                    "cdnjs", "jsdelivr", "unpkg", "ajax.googleapis.com",
                    "ajax.microsoft.com", "code.jquery.com", "stackpath", "maxcdn",
                    "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com",
                    "firebase", "segment.com", "segment.io", "doubleclick",
                    "googletagmanager.com", "hotjar.com",
                    "cloudflareinsights.com", "cdn.cookielaw.org",
                    "dc.services.visualstudio.com",
                    "launchdarkly.com", "data.microsoft.com",
                    "rs.fullstory.com", "edge.fullstory.com",
                    "sentry.io", "bat.bing.com", "snap.licdn.com",
                    "platform.linkedin.com", "connect.facebook.net",
                    "static.klaviyo.com", "static.ads-twitter.com",
                    "akamaiedge.net",
                    "online-metrix.net",
                    "microsoftonline.com",
                    "msauth.net",
                    "msftauth.net",
                    "live.com",
                    "adobedtm.com",
                    "omtrdc.net",
                    "demdex.net",
                    "google-analytics.com",
                    "nr-data.net",
                    "medallia.com",
                    "medallia.eu"
            ));
        }
    }
}
