package com.secretscanner;

import com.secretscanner.core.FindingMeta;
import com.secretscanner.core.ValidationRule;
import com.secretscanner.core.Validators;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Applies the offline validation checks a user has selected to findings. Runs only when the user
 * turns validation on (the Dashboard "Validate" toggle); contacts nothing. Each finding gets a
 * {@link FindingMeta.Validation} state and a short note.
 */
final class ValidationRunner {

    private ValidationRunner() {}

    /** Parsed custom rule: a pattern over the value and the state to assign on a match. */
    private record Custom(Pattern pattern, FindingMeta.Validation state, String note) {}

    /** Validates one finding against the enabled catalog entries and custom rules; returns a copy. */
    static SecretFinding validate(SecretFinding f, ScanSettings settings, long nowMillis) {
        if (f == null) return null;
        String value = f.matchedValue();
        // user custom rules win: they encode the team's own knowledge (e.g. "our sandbox prefix")
        for (Custom c : parseCustom(settings.getValidationCustomRules())) {
            Validators.Result r = Validators.regex(value, c.pattern(), c.state(), c.note());
            if (r.state() != FindingMeta.Validation.NOT_CHECKED || !r.note().isEmpty())
                return apply(f, r);
        }
        Set<String> enabled = settings.getValidationEnabledIds();
        if (!enabled.contains(f.ruleId())) return f;
        ValidationRule rule = ValidationCatalog.forRuleId(f.ruleId());
        if (rule == null) return f;
        if (rule.check().isOffline()) {
            Validators.Result res = switch (rule.check()) {
                case JWT_EXPIRY -> Validators.jwtExpiry(value, nowMillis);
                case LUHN       -> Validators.luhn(value);
                default         -> Validators.NONE;
            };
            return apply(f, res);
        }
        // LIVE: a real request to the provider. Off unless the operator opted into network validation.
        if (!settings.isLiveValidationEnabled()) return f;
        return apply(f, live(rule.provider(), value, settings));
    }

    /** Runs one live verify request for a LIVE provider, honouring any user endpoint override. */
    private static Validators.Result live(String provider, String value, ScanSettings settings) {
        com.secretscanner.core.ValidationEndpoints.Call call =
                com.secretscanner.core.ValidationEndpoints.resolveCall(provider, settings.validationBaseUrlMap().get(provider));
        if (call == null) return Validators.NONE;                       // no usable endpoint for this provider
        com.secretscanner.core.ValidationEndpoints.Auth auth =
                com.secretscanner.core.ValidationEndpoints.authFor(provider);
        com.secretscanner.core.LiveValidator.Result r =
                com.secretscanner.core.LiveValidator.check(call.method(), call.url(), auth.scheme(), auth.detail(), value, 8);
        return new Validators.Result(r.state(), r.note());
    }

    private static SecretFinding apply(SecretFinding f, Validators.Result r) {
        if (r == null || (r.state() == FindingMeta.Validation.NOT_CHECKED && r.note().isEmpty())) return f;
        FindingMeta m = f.meta().withValidation(r.state());
        if (!r.note().isEmpty()) m = m.withReason(r.note());
        return f.withMeta(m);
    }

    /** Parses custom rule lines: {@code name | regex | STATE[ | note]}. Bad lines are skipped. */
    private static List<Custom> parseCustom(List<String> lines) {
        List<Custom> out = new ArrayList<>();
        if (lines == null) return out;
        for (String line : lines) {
            if (line == null || line.isBlank() || line.trim().startsWith("#")) continue;
            String[] p = line.split("\\|");
            if (p.length < 3) continue;
            FindingMeta.Validation state;
            try { state = FindingMeta.Validation.valueOf(p[2].trim().toUpperCase(java.util.Locale.ROOT)); }
            catch (IllegalArgumentException e) { continue; }
            Pattern pat;
            try { pat = Pattern.compile(p[1].trim()); }
            catch (PatternSyntaxException e) { continue; }
            String note = p.length >= 4 ? p[3].trim() : (p[0].trim() + " matched");
            out.add(new Custom(pat, state, note));
        }
        return out;
    }
}
