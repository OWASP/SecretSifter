package com.secretscanner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Thread-safe settings model (Burp-free ZAP variant).
 *
 * <p>Primitive fields use volatile for cross-thread visibility; the CDN / key
 * lists are guarded by synchronized methods.  Persistence is handled by the ZAP
 * options layer (see {@code SecretSifterParam}); this class is a plain in-memory
 * model with sane defaults.  AI-triage and MCP settings from the Burp edition are
 * intentionally omitted — the ZAP add-on is a passive scanner only.
 */
public class ScanSettings {

    public enum ScanTier { FAST, LIGHT, FULL }

    // ---- fields ----
    private volatile boolean   enabled              = true;
    private volatile ScanTier  tier                 = ScanTier.FULL;
    private volatile double    entropyThreshold     = 3.5;
    private volatile boolean   piiEnabled           = true;
    private volatile boolean   scanRequestsEnabled  = true;
    private volatile boolean   customRulesEnabled   = true;
    // Raw mode: run ONLY user-supplied custom rules and bypass FP gates.
    private volatile boolean   customRulesOnly      = false;

    // Key name blocklist — findings whose matched key name contains any entry are suppressed.
    private final List<String> keyBlocklist = new ArrayList<>(Arrays.asList(
            "STORAGE_KEY_", "storage_key_",
            "STATE_KEY_",   "state_key_",
            "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
    ));

    // Key name allowlist — findings whose matched key name contains any entry are always reported.
    private final List<String> keyAllowlist = new ArrayList<>();

    // Custom rules — "RuleName | regex | severity" lines parsed at scan time.
    private final List<String> customRules = new ArrayList<>();

    private final List<String> cdnBlocklist = new ArrayList<>(Arrays.asList(
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

    public boolean isCustomRulesEnabled()                { return customRulesEnabled; }
    public void    setCustomRulesEnabled(boolean b)      { customRulesEnabled = b; }
    public boolean isCustomRulesOnly()                   { return customRulesOnly; }
    public void    setCustomRulesOnly(boolean b)         { customRulesOnly = b; }

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
     * or if the hostname itself starts with "cdn.".  Applied to the HOSTNAME only.
     */
    public boolean isExternalCdn(String urlOrHost) {
        if (urlOrHost == null || urlOrHost.isBlank()) return false;
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
        if (host.startsWith("cdn.") || host.equals("cdn")) return true;
        synchronized (this) {
            for (String entry : cdnBlocklist) {
                String e = entry.toLowerCase();
                if (host.equals(e) || host.endsWith("." + e)) return true;
            }
        }
        return false;
    }

    public void resetToDefaults() {
        enabled              = true;
        tier                 = ScanTier.FULL;
        entropyThreshold     = 3.5;
        piiEnabled           = true;
        scanRequestsEnabled  = true;
        customRulesEnabled   = true;
        customRulesOnly      = false;
        synchronized (this) {
            keyBlocklist.clear();
            keyBlocklist.addAll(Arrays.asList(
                    "STORAGE_KEY_", "storage_key_",
                    "STATE_KEY_",   "state_key_",
                    "NEXT_PUBLIC_", "REACT_APP_PUBLIC_", "VUE_APP_PUBLIC_"
            ));
            keyAllowlist.clear();
            customRules.clear();
        }
    }
}
