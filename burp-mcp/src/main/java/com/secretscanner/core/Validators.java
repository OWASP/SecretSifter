package com.secretscanner.core;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Offline secret checks. Every method here runs entirely on the local machine: it decodes, parses
 * or pattern-matches the value and returns a confidence verdict. Nothing is ever sent anywhere, so
 * these are always safe to run and need no authorization.
 *
 * Live checks that contact a provider to confirm a credential is accepted are a separate layer and
 * are not implemented here.
 */
public final class Validators {

    /** A verdict plus a short human note; {@link #NONE} means "no offline signal, leave unchanged". */
    public record Result(FindingMeta.Validation state, String note) {}

    public static final Result NONE = new Result(FindingMeta.Validation.NOT_CHECKED, "");

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd")
            .withZone(ZoneOffset.UTC);
    private static final Pattern JSON_NUM = Pattern.compile("\"%s\"\\s*:\\s*(\\d{1,15})");

    private Validators() {}

    /**
     * JWT: an expired token is dead (INACTIVE); a readable, unexpired one is annotated but not
     * claimed active (only the server can confirm that); anything that is not a decodable JWT with
     * an {@code exp} claim yields no signal.
     */
    public static Result jwtExpiry(String value, long nowMillis) {
        if (value == null) return NONE;
        String v = value.trim();
        int d1 = v.indexOf('.');
        int d2 = d1 < 0 ? -1 : v.indexOf('.', d1 + 1);
        if (d1 <= 0 || d2 <= d1) return NONE;
        String json;
        try {
            json = new String(Base64.getUrlDecoder().decode(pad(v.substring(d1 + 1, d2))), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return NONE;
        }
        Long exp = jsonLong(json, "exp");
        if (exp == null) return NONE;
        long expMs = exp * 1000L;
        if (expMs < nowMillis)
            return new Result(FindingMeta.Validation.INACTIVE, "JWT expired " + ISO.format(Instant.ofEpochMilli(expMs)));
        return new Result(FindingMeta.Validation.NOT_CHECKED, "JWT not expired (exp " + ISO.format(Instant.ofEpochMilli(expMs)) + ")");
    }

    /** Credit-card number: fails the Luhn check -> not a real card (INACTIVE); passes -> no signal. */
    public static Result luhn(String value) {
        if (value == null) return NONE;
        String digits = value.replaceAll("[^0-9]", "");
        if (digits.length() < 12 || digits.length() > 19) return NONE;
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0 ? NONE : new Result(FindingMeta.Validation.INACTIVE, "fails Luhn check");
    }

    /** User rule: if {@code value} matches {@code pattern}, return {@code onMatch}; otherwise no signal. */
    public static Result regex(String value, Pattern pattern, FindingMeta.Validation onMatch, String note) {
        if (value == null || pattern == null) return NONE;
        return pattern.matcher(value).find() ? new Result(onMatch, note == null ? "" : note) : NONE;
    }

    /** Base64url padding so {@link Base64#getUrlDecoder()} accepts an unpadded segment. */
    private static String pad(String s) {
        int rem = s.length() % 4;
        return rem == 0 ? s : s + "====".substring(rem);
    }

    /** Integer value of a top-level numeric JSON field, or null. No JSON library: a bounded regex. */
    static Long jsonLong(String json, String field) {
        Matcher m = Pattern.compile(String.format(JSON_NUM.pattern(), Pattern.quote(field))).matcher(json);
        if (!m.find()) return null;
        try { return Long.parseLong(m.group(1)); } catch (NumberFormatException e) { return null; }
    }
}
