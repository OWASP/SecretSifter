package com.secretscanner;

/**
 * Immutable record representing a single secret finding.
 *
 * <p>This is the Burp-free variant used by the ZAP add-on.  It carries only the
 * data the detection engine produces; conversion to a ZAP {@code Alert} lives in
 * the ZAP glue layer (see {@code org.zaproxy.zap.extension.secretsifter}).
 */
public record SecretFinding(
        String ruleId,
        String ruleName,
        String keyName,
        String matchedValue,
        String severity,    // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"
        String confidence,  // "CERTAIN", "FIRM", "TENTATIVE"
        int    lineNumber,
        String context,
        String sourceUrl,
        String targetUrl,   // original input target from bulk scan; "" for proxy findings
        int    matchOffset  // byte offset of the match within the body; -1 if unknown
) {
    /** Convenience factory — targetUrl defaults to "" and offset to -1. */
    public static SecretFinding of(String ruleId, String ruleName,
            String key, String value, String severity, String confidence,
            int line, String context, String url) {
        return new SecretFinding(ruleId, ruleName, key, value,
                severity, confidence, line, context, url, "", -1);
    }

    /** Factory that captures byte offset of the match for per-occurrence dedup. */
    public static SecretFinding of(String ruleId, String ruleName,
            String key, String value, String severity, String confidence,
            int line, String context, String url, int offset) {
        return new SecretFinding(ruleId, ruleName, key, value,
                severity, confidence, line, context, url, "", offset);
    }

    /** Returns a copy of this finding with severity overridden. */
    public SecretFinding withSeverity(String newSeverity) {
        return new SecretFinding(ruleId, ruleName, keyName, matchedValue,
                newSeverity, confidence, lineNumber, context, sourceUrl, targetUrl, matchOffset);
    }

    /** Returns a copy of this finding with targetUrl set to the given origin target. */
    public SecretFinding withTargetUrl(String origin) {
        return new SecretFinding(ruleId, ruleName, keyName, matchedValue,
                severity, confidence, lineNumber, context, sourceUrl, origin, matchOffset);
    }
}