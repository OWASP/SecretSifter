package com.secretsifter.core;

/**
 * One entry in the validation catalog: how to check findings from a given detection rule (or a
 * user-defined pattern). Immutable, no Burp dependency.
 *
 * @param id        catalog id — the detection rule id it applies to, or {@code custom:<name>}
 * @param provider  vendor/service it is grouped under in the UI (e.g. "AWS", "GitHub")
 * @param name      display name shown in the selector
 * @param check     which offline/live check to run
 * @param detail    check-specific detail: for REGEX, "pattern => STATE"; otherwise ""
 * @param defaultOn whether this entry is selected out of the box
 */
public record ValidationRule(String id, String provider, String name, CheckType check,
                             String detail, boolean defaultOn) {

    public enum CheckType {
        JWT_EXPIRY("Offline: JWT expiry"),
        LUHN("Offline: Luhn check"),
        REGEX("Offline: your pattern"),
        LIVE("Live (network, opt-in)");

        private final String label;
        CheckType(String label) { this.label = label; }
        public String label() { return label; }
        /** True when the check runs fully offline (safe to run with no authorization). */
        public boolean isOffline() { return this != LIVE; }
    }
}
