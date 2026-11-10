package com.secretsifter;


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

    // ---- preference keys ----
    private static final String KEY_ENABLED        = "ss.enabled";
    private static final String KEY_TIER           = "ss.tier";
    private static final String KEY_ENTROPY        = "ss.entropy";        // stored as String
    private static final String KEY_PII            = "ss.pii";
    private static final String KEY_CDNLIST        = "ss.cdnlist";        // newline-separated
    private static final String KEY_SCAN_REQUESTS  = "ss.scan_requests";
    private static final String KEY_KEY_BLOCKLIST  = "ss.keyblocklist";   // newline-separated
    private static final String KEY_KEY_ALLOWLIST  = "ss.keyallowlist";   // newline-separated
    private static final String KEY_PW_ENABLED     = "ss.pw.enabled";
    private static final String KEY_PW_MAXPAGES    = "ss.pw.maxpages";    // stored as String
    private static final String KEY_BROWSER_PATH        = "ss.browser.path";
    private static final String KEY_CUSTOM_RULES         = "ss.customrules";
    private static final String KEY_CUSTOM_RULES_ENABLED = "ss.customrules_enabled";
    private static final String KEY_CUSTOM_RULES_ONLY    = "ss.customrules_only";
    private static final String KEY_URL_TIMEOUT          = "ss.url_timeout";
    private static final String KEY_CROSS_ORIGIN_APIS    = "ss.cross_origin_apis";
    private static final String KEY_STRICT_SCOPE          = "ss.strict_scope";
    private static final String KEY_VALIDATION_ENABLED    = "ss.validation_enabled";
    private static final String KEY_LIVE_VALIDATION       = "ss.live_validation_enabled"; // master network opt-in (off by default)
    private static final String KEY_VALIDATION_IDS        = "ss.validation_ids";        // newline-separated catalog ids
    private static final String KEY_VALIDATION_IDS_SET    = "ss.validation_ids_set";    // "1" once the user has saved a selection
    private static final String KEY_VALIDATION_CUSTOM     = "ss.validation_custom";     // newline-separated custom rule lines
    private static final String KEY_VALIDATION_BASEURLS   = "ss.validation_baseurls";   // newline-separated "provider = https://host" lines

    // ---- fields ----
    private volatile boolean   enabled              = true;
    private volatile ScanTier  tier                 = ScanTier.FULL;
    private volatile double    entropyThreshold     = 3.5;
    private volatile boolean   piiEnabled           = true;
    private volatile boolean   scanRequestsEnabled  = true;
    private volatile boolean   playwrightEnabled    = false;
    private volatile int       playwrightMaxPages   = 100;
    private volatile String    browserPath          = "";

    private final List<String> customRules        = new ArrayList<>();
    private volatile boolean   customRulesEnabled = true;
    private volatile boolean   customRulesOnly    = false;
    private volatile int       urlTimeoutSeconds      = 0;   // 0 = no limit
    private volatile boolean   followCrossOriginApis  = false;
    private volatile boolean   strictScope            = false;

    // Live key validation (opt-in, off by default). Mirrors the Burp MCP edition.
    private volatile boolean validationEnabled = false;
    private volatile boolean liveValidationEnabled = false;   // network validation: off until the operator opts in
    private final java.util.Set<String> validationEnabledIds = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile boolean validationIdsInitialised = false;
    private final List<String> validationCustomRules = new ArrayList<>();
    private final List<String> validationBaseUrls = new ArrayList<>();   // "provider = https://host" lines (self-hosted overrides)

    // Key name blocklist — findings whose matched key name contains any entry are suppressed.
    private final List<String> keyBlocklist = new ArrayList<>(Arrays.asList(
            "STORAGE_KEY_", "storage_key_",
            "STATE_KEY_",   "state_key_",
            "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
    ));

    // Key name allowlist — always reported, bypasses isProbableSecretValue() checks.
    private final List<String> keyAllowlist = new ArrayList<>();

    private final List<String> cdnBlocklist = new ArrayList<>(Arrays.asList(
            // JS/CSS CDNs — static asset delivery, no secrets expected
            "cdnjs", "jsdelivr", "unpkg", "ajax.googleapis.com",
            "ajax.microsoft.com", "code.jquery.com", "stackpath", "maxcdn",
            "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com",
            // Analytics / tracking — no secrets, just noise
            "firebase", "segment.com", "segment.io", "doubleclick",
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
            "online-metrix.net"         // ThreatMetrix / LexisNexis Risk Solutions
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

    public boolean isPiiEnabled()                { return piiEnabled; }
    public void    setPiiEnabled(boolean b)      { piiEnabled = b; }

    public boolean isScanRequestsEnabled()               { return scanRequestsEnabled; }
    public void    setScanRequestsEnabled(boolean b)     { scanRequestsEnabled = b; }

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
        for (String entry : keyBlocklist) {
            if (!entry.isBlank() && kl.contains(entry.toLowerCase())) return true;
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

    /** Returns true if the key name contains any entry in the key allowlist (case-insensitive). */
    public synchronized boolean isKeyAllowlisted(String keyName) {
        if (keyName == null || keyAllowlist.isEmpty()) return false;
        String kl = keyName.toLowerCase();
        for (String entry : keyAllowlist) {
            if (!entry.isBlank() && kl.contains(entry.toLowerCase())) return true;
        }
        return false;
    }

    public boolean isPlaywrightEnabled()             { return playwrightEnabled; }
    public void    setPlaywrightEnabled(boolean b)   { playwrightEnabled = b; }

    public int  getPlaywrightMaxPages()              { return playwrightMaxPages; }
    public void setPlaywrightMaxPages(int n)         { playwrightMaxPages = Math.max(1, Math.min(n, 2000)); }

    public String getBrowserPath()                   { return browserPath != null ? browserPath : ""; }
    public void   setBrowserPath(String p)           { browserPath = p != null ? p : ""; }

    public synchronized List<String> getCustomRules() {
        return new ArrayList<>(customRules);
    }
    public synchronized void setCustomRules(List<String> rules) {
        customRules.clear();
        if (rules != null) customRules.addAll(rules);
    }
    public boolean isCustomRulesEnabled()           { return customRulesEnabled; }
    public void    setCustomRulesEnabled(boolean b) { customRulesEnabled = b; }
    public boolean isCustomRulesOnly()              { return customRulesOnly; }
    public void    setCustomRulesOnly(boolean b)    { customRulesOnly = b; }

    /** Per-URL wall-clock timeout in seconds. 0 means no limit (current behaviour). */
    public int  getUrlTimeoutSeconds()      { return urlTimeoutSeconds; }
    public void setUrlTimeoutSeconds(int s) { urlTimeoutSeconds = Math.max(0, s); }

    /** When true, browser mode scans JSON/XML responses from cross-origin API calls
     *  (e.g. app.example.com calling api.other-service.com). Default: false. */
    public boolean isFollowCrossOriginApis()           { return followCrossOriginApis; }
    public void    setFollowCrossOriginApis(boolean b) { followCrossOriginApis = b; }

    /** When true, JS resource capture in browser mode requires exact host match (not same
     *  registrable domain). Equivalent to Burp's strict target scope. Default: false. */
    public boolean isStrictScope()           { return strictScope; }
    public void    setStrictScope(boolean b) { strictScope = b; }

    public synchronized List<String> getCdnBlocklist() {
        return new ArrayList<>(cdnBlocklist);
    }

    public synchronized void setCdnBlocklist(List<String> list) {
        cdnBlocklist.clear();
        if (list != null) cdnBlocklist.addAll(list);
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
        // Broad heuristic: any hostname starting with "cdn." is an asset CDN
        if (host.startsWith("cdn.") || host.equals("cdn")) return true;
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
    // Live key validation (opt-in). Mirrors the Burp MCP edition.
    // =========================================================================

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
        for (com.secretsifter.core.ValidationRule vr : ValidationCatalog.builtIn())
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

    // =========================================================================
    // Persistence
    // =========================================================================

    public void saveToPrefs(AppPrefs prefs) {
        try {
            prefs.setBoolean(KEY_ENABLED,         enabled);
            prefs.setString(KEY_TIER,             tier.name());
            prefs.setString(KEY_ENTROPY,          String.valueOf(entropyThreshold));
            prefs.setBoolean(KEY_PII,             piiEnabled);
            prefs.setBoolean(KEY_SCAN_REQUESTS,   scanRequestsEnabled);
            prefs.setString(KEY_CDNLIST,          String.join("\n", getCdnBlocklist()));
            prefs.setString(KEY_KEY_BLOCKLIST,    String.join("\n", getKeyBlocklist()));
            prefs.setString(KEY_KEY_ALLOWLIST,    String.join("\n", getKeyAllowlist()));
            prefs.setBoolean(KEY_PW_ENABLED,      playwrightEnabled);
            prefs.setString(KEY_PW_MAXPAGES,   String.valueOf(playwrightMaxPages));
            prefs.setString(KEY_BROWSER_PATH,  browserPath);
            prefs.setString(KEY_CUSTOM_RULES,  String.join("\n", getCustomRules()));
            prefs.setBoolean(KEY_CUSTOM_RULES_ENABLED, customRulesEnabled);
            prefs.setBoolean(KEY_CUSTOM_RULES_ONLY,    customRulesOnly);
            prefs.setString(KEY_URL_TIMEOUT,   String.valueOf(urlTimeoutSeconds));
            prefs.setBoolean(KEY_CROSS_ORIGIN_APIS, followCrossOriginApis);
            prefs.setBoolean(KEY_STRICT_SCOPE,      strictScope);
            prefs.setBoolean(KEY_VALIDATION_ENABLED, validationEnabled);
            prefs.setBoolean(KEY_LIVE_VALIDATION,    liveValidationEnabled);
            prefs.setString(KEY_VALIDATION_IDS,      String.join("\n", getValidationEnabledIds()));
            prefs.setBoolean(KEY_VALIDATION_IDS_SET, validationIdsInitialised);
            prefs.setString(KEY_VALIDATION_CUSTOM,   String.join("\n", validationCustomRules));
            prefs.setString(KEY_VALIDATION_BASEURLS, String.join("\n", validationBaseUrls));
        } catch (Exception ignored) {
            // Preferences not critical — continue silently
        }
    }

    public void loadFromPrefs(AppPrefs prefs) {
        try {
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

            String cdnStr = prefs.getString(KEY_CDNLIST);
            if (cdnStr != null && !cdnStr.isBlank()) {
                List<String> loaded = new ArrayList<>();
                for (String line : cdnStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setCdnBlocklist(loaded);
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

            Boolean pwEn = prefs.getBoolean(KEY_PW_ENABLED);
            if (pwEn != null) playwrightEnabled = pwEn;

            String pwPages = prefs.getString(KEY_PW_MAXPAGES);
            if (pwPages != null) {
                try { playwrightMaxPages = Integer.parseInt(pwPages.trim()); }
                catch (NumberFormatException ignored2) {}
            }

            String bPath = prefs.getString(KEY_BROWSER_PATH);
            if (bPath != null) browserPath = bPath;

            String customRulesStr = prefs.getString(KEY_CUSTOM_RULES);
            if (customRulesStr != null && !customRulesStr.isBlank()) {
                List<String> loaded = new ArrayList<>();
                for (String line : customRulesStr.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) loaded.add(trimmed);
                }
                setCustomRules(loaded);
            }
            Boolean customRulesEn = prefs.getBoolean(KEY_CUSTOM_RULES_ENABLED);
            if (customRulesEn != null) customRulesEnabled = customRulesEn;

            Boolean customRulesOnlyB = prefs.getBoolean(KEY_CUSTOM_RULES_ONLY);
            if (customRulesOnlyB != null) customRulesOnly = customRulesOnlyB;

            String urlTimeoutStr = prefs.getString(KEY_URL_TIMEOUT);
            if (urlTimeoutStr != null) {
                try { urlTimeoutSeconds = Math.max(0, Integer.parseInt(urlTimeoutStr.trim())); }
                catch (NumberFormatException ignored2) {}
            }

            Boolean crossOrigin = prefs.getBoolean(KEY_CROSS_ORIGIN_APIS);
            if (crossOrigin != null) followCrossOriginApis = crossOrigin;

            Boolean strict = prefs.getBoolean(KEY_STRICT_SCOPE);
            if (strict != null) strictScope = strict;

            Boolean valEn = prefs.getBoolean(KEY_VALIDATION_ENABLED);
            if (valEn != null) validationEnabled = valEn;

            Boolean liveEn = prefs.getBoolean(KEY_LIVE_VALIDATION);
            if (liveEn != null) liveValidationEnabled = liveEn;

            Boolean idsSet = prefs.getBoolean(KEY_VALIDATION_IDS_SET);
            if (idsSet != null && idsSet) {
                String idsStr = prefs.getString(KEY_VALIDATION_IDS);
                List<String> loaded = new ArrayList<>();
                if (idsStr != null) for (String line : idsStr.split("\n")) {
                    String t = line.trim();
                    if (!t.isEmpty()) loaded.add(t);
                }
                setValidationEnabledIds(loaded);
            }

            String valCustom = prefs.getString(KEY_VALIDATION_CUSTOM);
            if (valCustom != null && !valCustom.isBlank())
                setValidationCustomRules(Arrays.asList(valCustom.split("\n")));

            String valBase = prefs.getString(KEY_VALIDATION_BASEURLS);
            if (valBase != null && !valBase.isBlank())
                setValidationBaseUrls(Arrays.asList(valBase.split("\n")));

        } catch (Exception ignored) {}
    }

    public void resetToDefaults() {
        enabled              = true;
        tier                 = ScanTier.FULL;
        entropyThreshold     = 3.5;
        piiEnabled           = true;
        scanRequestsEnabled  = true;
        playwrightEnabled      = false;
        playwrightMaxPages     = 100;
        browserPath            = "";
        customRulesEnabled     = true;
        customRulesOnly        = false;
        urlTimeoutSeconds      = 0;
        followCrossOriginApis  = false;
        strictScope            = false;
        validationEnabled      = false;
        liveValidationEnabled  = false;
        validationIdsInitialised = false;
        synchronized (this) {
            validationEnabledIds.clear();
            validationCustomRules.clear();
            validationBaseUrls.clear();
            customRules.clear();
            keyBlocklist.clear();
            keyBlocklist.addAll(Arrays.asList(
                    "STORAGE_KEY_", "storage_key_",
                    "STATE_KEY_",   "state_key_",
                    "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
            ));
            keyAllowlist.clear();
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
                    "akamaiedge.net", "online-metrix.net"
            ));
        }
    }
}
