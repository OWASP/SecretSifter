package com.secretscanner.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Analysis data attached to a finding, beyond what the scanner originally reported.
 *
 * Kept separate from the finding's identity (rule, value, location): a finding's meta can be
 * enriched (scored, validated, linked to an asset) without it becoming a different finding.
 * Immutable; the {@code with*} methods return copies. Has no Burp dependency.
 */
public record FindingMeta(
        int          score,        // 0-100 confidence that this is a real, usable secret; -1 = not scored
        List<String> reasons,      // reason codes behind the score, e.g. "anchored-rule", "checksum-ok"
        List<String> decodeChain,  // decoders applied to reach the value, outermost first, e.g. ["base64"]
        String       asset,        // resource the secret belongs to (host, tenant, endpoint); "" = unknown
        Validation   validation    // live-validation state
) {
    /** Live-validation state of a secret. */
    public enum Validation {
        NOT_CHECKED,  // validation not run (default; validation is opt-in)
        ACTIVE,       // provider accepted the secret
        INACTIVE,     // provider rejected it (revoked, expired, invalid)
        RESTRICTED,   // accepted but limited in scope (e.g. HTTP 403 on the probe)
        UNKNOWN       // could not tell (timeout, rate limit, unexpected response); never treated as dead
    }

    public static final int NOT_SCORED = -1;

    public static final FindingMeta EMPTY =
            new FindingMeta(NOT_SCORED, List.of(), List.of(), "", Validation.NOT_CHECKED);

    public FindingMeta {
        if (score < NOT_SCORED || score > 100) throw new IllegalArgumentException("score out of range: " + score);
        reasons     = reasons     == null ? List.of() : List.copyOf(reasons);
        decodeChain = decodeChain == null ? List.of() : List.copyOf(decodeChain);
        asset       = asset       == null ? "" : asset;
        validation  = validation  == null ? Validation.NOT_CHECKED : validation;
    }

    public boolean isScored() { return score != NOT_SCORED; }

    public FindingMeta withScore(int newScore, List<String> newReasons) {
        return new FindingMeta(newScore, newReasons, decodeChain, asset, validation);
    }

    public FindingMeta withReason(String reason) {
        List<String> r = new ArrayList<>(reasons);
        if (!r.contains(reason)) r.add(reason);
        return new FindingMeta(score, r, decodeChain, asset, validation);
    }

    public FindingMeta withDecodeChain(List<String> chain) {
        return new FindingMeta(score, reasons, chain, asset, validation);
    }

    public FindingMeta withAsset(String newAsset) {
        return new FindingMeta(score, reasons, decodeChain, newAsset, validation);
    }

    public FindingMeta withValidation(Validation newValidation) {
        return new FindingMeta(score, reasons, decodeChain, asset, newValidation);
    }
}
