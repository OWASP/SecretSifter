package com.secretscanner;

import com.secretscanner.core.FindingMeta;
import com.secretscanner.core.ValidationRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Validation catalog and runner")
class ValidationTest {

    private static final long NOW = 1_700_000_000_000L;

    private static SecretFinding finding(String ruleId, String value) {
        return SecretFinding.of(ruleId, ruleId, "k", value, "HIGH", "FIRM", 1, "ctx", "https://x.test/a.js");
    }

    private static String expiredJwt() {
        String p = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"exp\":1600000000}".getBytes(StandardCharsets.UTF_8));
        return "eyJhbGciOiJIUzI1NiJ9." + p + ".c2ln";
    }

    @Test void catalogGroupsByProviderAndFlagsOfflineChecks() {
        ValidationRule jwt = ValidationCatalog.forRuleId("JWT_TOKEN_001");
        assertNotNull(jwt);
        assertEquals(ValidationRule.CheckType.JWT_EXPIRY, jwt.check());
        assertTrue(jwt.check().isOffline());
        assertTrue(ValidationCatalog.byProvider().size() > 5, "providers should be grouped");
        // a vendor token with no offline check is present but marked live
        ValidationRule aws = ValidationCatalog.forRuleId("AWS_KEY_001");
        assertNotNull(aws);
        assertEquals(ValidationRule.CheckType.LIVE, aws.check());
    }

    @Test void expiredJwtFindingIsMarkedDeadWhenEnabled() {
        ScanSettings s = new ScanSettings();
        s.setValidationEnabledIds(Set.of("JWT_TOKEN_001"));
        SecretFinding out = ValidationRunner.validate(finding("JWT_TOKEN_001", expiredJwt()), s, NOW);
        assertEquals(FindingMeta.Validation.INACTIVE, out.meta().validation());
    }

    @Test void disabledRuleLeavesFindingUnchecked() {
        ScanSettings s = new ScanSettings();
        s.setValidationEnabledIds(Set.of());   // JWT not selected
        SecretFinding out = ValidationRunner.validate(finding("JWT_TOKEN_001", expiredJwt()), s, NOW);
        assertEquals(FindingMeta.Validation.NOT_CHECKED, out.meta().validation());
    }

    @Test void liveRuleIsSkippedOffline() {
        ScanSettings s = new ScanSettings();
        s.setValidationEnabledIds(Set.of("AWS_KEY_001"));
        SecretFinding out = ValidationRunner.validate(finding("AWS_KEY_001", "AKIAEXAMPL" + "E1234567890"), s, NOW);
        assertEquals(FindingMeta.Validation.NOT_CHECKED, out.meta().validation());
    }

    @Test void customRuleMarksSandboxKeyDead() {
        ScanSettings s = new ScanSettings();
        s.setValidationCustomRules(List.of("sandbox | ^sk_test_ | INACTIVE | our test key"));
        SecretFinding out = ValidationRunner.validate(finding("STRIPE_KEY_002", "sk_test_abc123def456"), s, NOW);
        assertEquals(FindingMeta.Validation.INACTIVE, out.meta().validation());
    }

    @Test void defaultSelectionIncludesOfflineAndLive() {
        // Default selection is every catalog entry so turning Validate on checks everything applicable.
        // Live entries are selected but only contact the network when the live-validation switch is on
        // (see liveRuleIsSkippedOffline).
        Set<String> def = new ScanSettings().getValidationEnabledIds();
        assertTrue(def.contains("JWT_TOKEN_001"));   // offline
        assertTrue(def.contains("AWS_KEY_001"));     // live (selected; network-gated separately)
    }
}
