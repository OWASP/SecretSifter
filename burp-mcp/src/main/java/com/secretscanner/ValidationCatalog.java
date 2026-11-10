package com.secretscanner;

import com.secretscanner.core.ValidationRule;
import com.secretscanner.core.ValidationRule.CheckType;
import com.secretscanner.rules.RuleDef;
import com.secretscanner.rules.RuleLoader;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The validation catalog: one {@link ValidationRule} per built-in detection rule, grouped by
 * provider, plus any user-defined custom rules. The Settings "Validation" block renders this so a
 * user can pick, per provider, which findings get validated.
 *
 * Built once from the detection rule files (their {@code provider} metadata gives the grouping). A
 * rule gets an offline check when one applies (JWT expiry, Luhn); otherwise it is marked LIVE, shown
 * for completeness and selected by the user for when the live layer is available.
 */
public final class ValidationCatalog {

    private static final List<ValidationRule> BUILT_IN = build();

    private ValidationCatalog() {}

    /** All built-in catalog entries, in load order. */
    public static List<ValidationRule> builtIn() {
        return BUILT_IN;
    }

    /** Catalog entries grouped by provider, provider names sorted, entries in load order. */
    public static Map<String, List<ValidationRule>> byProvider() {
        Map<String, List<ValidationRule>> out = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (ValidationRule r : BUILT_IN)
            out.computeIfAbsent(r.provider(), k -> new ArrayList<>()).add(r);
        return out;
    }

    /** Catalog entry for a detection rule id, or null if the id is not in the catalog. */
    public static ValidationRule forRuleId(String ruleId) {
        for (ValidationRule r : BUILT_IN) if (r.id().equals(ruleId)) return r;
        return null;
    }

    private static List<ValidationRule> build() {
        List<ValidationRule> out = new ArrayList<>();
        // de-dupe by rule id: a provider's key types each become one selectable entry
        Map<String, ValidationRule> byId = new LinkedHashMap<>();
        for (String resource : List.of(Patterns.ANCHORED_RULES_RESOURCE, Patterns.CONTEXT_RULES_RESOURCE)) {
            for (RuleDef d : RuleLoader.loadResource(resource)) {
                String provider = (d.provider() == null || d.provider().isBlank()) ? "Other" : d.provider();
                CheckType check = checkFor(d);
                byId.putIfAbsent(d.id(), new ValidationRule(
                        d.id(), provider, d.name() == null ? d.id() : d.name(),
                        check, "", check.isOffline()));
            }
        }
        out.addAll(byId.values());
        // code-based detectors that have no YAML rule but a real offline check
        out.add(new ValidationRule("CC_GROUPED", "Payment cards", "Credit card number",
                CheckType.LUHN, "", true));
        return List.copyOf(out);
    }

    /** Offline check for a detection rule, or LIVE when only a network check could confirm it. */
    private static CheckType checkFor(RuleDef d) {
        String id = d.id() == null ? "" : d.id();
        String pat = d.pattern() == null ? "" : d.pattern().pattern();
        if (id.startsWith("JWT_") || pat.contains("eyJ")) return CheckType.JWT_EXPIRY;
        return CheckType.LIVE;
    }
}
