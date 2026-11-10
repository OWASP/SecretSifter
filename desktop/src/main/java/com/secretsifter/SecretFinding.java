package com.secretsifter;

import com.secretsifter.core.FindingMeta;
import com.secretsifter.core.Fingerprints;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Immutable record representing a single secret finding.
 * Standalone desktop app — carries detection + validation metadata (no Burp/Montoya coupling).
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
        int    matchOffset, // byte offset of the match within the response body; -1 if unknown.
                            // Used in dedup so that minified bundles (where every match shares
                            // lineNumber=1 or one large line) still produce one finding per match.
        FindingMeta meta    // score, reasons, decode chain, asset, validation; never null.
                            // Not part of equals/hashCode: enriching a finding keeps its identity.
) {
    public SecretFinding {
        if (meta == null) meta = FindingMeta.EMPTY;
    }

    /** Pre-meta constructor, kept so existing callers compile unchanged; meta is empty. */
    public SecretFinding(String ruleId, String ruleName, String keyName, String matchedValue,
                         String severity, String confidence, int lineNumber, String context,
                         String sourceUrl, String targetUrl, int matchOffset) {
        this(ruleId, ruleName, keyName, matchedValue, severity, confidence, lineNumber, context,
                sourceUrl, targetUrl, matchOffset, FindingMeta.EMPTY);
    }

    /** Convenience factory — targetUrl defaults to "" and offset to -1 for backward compatibility. */
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

    /** Returns a copy of this finding with severity overridden to the given value. */
    public SecretFinding withSeverity(String newSeverity) {
        return new SecretFinding(ruleId, ruleName, keyName, matchedValue,
                newSeverity, confidence, lineNumber, context, sourceUrl, targetUrl, matchOffset, meta);
    }

    /** Returns a copy of this finding with targetUrl set to the given origin target. */
    public SecretFinding withTargetUrl(String origin) {
        return new SecretFinding(ruleId, ruleName, keyName, matchedValue,
                severity, confidence, lineNumber, context, sourceUrl, origin, matchOffset, meta);
    }

    /** Returns a copy of this finding with its analysis data replaced. */
    public SecretFinding withMeta(FindingMeta newMeta) {
        return new SecretFinding(ruleId, ruleName, keyName, matchedValue,
                severity, confidence, lineNumber, context, sourceUrl, targetUrl, matchOffset, newMeta);
    }

    /** Keyed fingerprint of the normalized secret value (see {@link Fingerprints}); safe to store and export. */
    public String fingerprint() {
        return com.secretsifter.core.IssueRegistry.fingerprint(matchedValue);
    }

    /** Permanent issue ID for this secret, e.g. {@code SS-102426-7K4M2Q}; the same secret always gets the same ID. */
    public String issueId() {
        return com.secretsifter.core.IssueRegistry.current().idFor(matchedValue);
    }

    /** ID of this particular sighting, e.g. {@code SS-102426-7K4M2Q@4f9a1c}: unique per location. */
    public String occurrenceRef() {
        return com.secretsifter.core.IssueRegistry.current()
                .occurrenceRef(matchedValue, sourceUrl, lineNumber, matchOffset, ruleId);
    }

    /** Validation state for reports/exports: {@code active}, {@code dead}, {@code restricted}, {@code unknown} or {@code not-checked}. */
    public String validationLabel() {
        return switch (meta.validation()) {
            case ACTIVE      -> "active";
            case INACTIVE    -> "dead";
            case RESTRICTED  -> "restricted";
            case UNKNOWN     -> "unknown";
            case NOT_CHECKED -> "not-checked";
        };
    }

    /** Returns a copy with confidence overridden (keeps offset and meta, unlike rebuilding via {@code of}). */
    public SecretFinding withConfidence(String newConfidence) {
        return new SecretFinding(ruleId, ruleName, keyName, matchedValue,
                severity, newConfidence, lineNumber, context, sourceUrl, targetUrl, matchOffset, meta);
    }

    /** The secret value with its middle masked, for display. */
    public String redactedValue() {
        return Fingerprints.redact(matchedValue);
    }

    /** Identity is the occurrence (all fields except {@link #meta}). */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SecretFinding f)) return false;
        return lineNumber == f.lineNumber && matchOffset == f.matchOffset
                && java.util.Objects.equals(ruleId, f.ruleId)
                && java.util.Objects.equals(ruleName, f.ruleName)
                && java.util.Objects.equals(keyName, f.keyName)
                && java.util.Objects.equals(matchedValue, f.matchedValue)
                && java.util.Objects.equals(severity, f.severity)
                && java.util.Objects.equals(confidence, f.confidence)
                && java.util.Objects.equals(context, f.context)
                && java.util.Objects.equals(sourceUrl, f.sourceUrl)
                && java.util.Objects.equals(targetUrl, f.targetUrl);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(ruleId, ruleName, keyName, matchedValue, severity, confidence,
                lineNumber, context, sourceUrl, targetUrl, matchOffset);
    }

}
