package com.secretscanner.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Offline validators")
class ValidatorsTest {

    private static final long NOW = 1_700_000_000_000L;  // 2023-11-14

    private static String jwt(String payloadJson) {
        String p = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return "eyJhbGciOiJub25lIn0." + p + ".c2ln";
    }

    @Test void expiredJwtIsDead() {
        Validators.Result r = Validators.jwtExpiry(jwt("{\"exp\":1600000000}"), NOW);   // 2020
        assertEquals(FindingMeta.Validation.INACTIVE, r.state());
        assertTrue(r.note().startsWith("JWT expired"), r.note());
    }

    @Test void unexpiredJwtIsAnnotatedNotClaimedActive() {
        Validators.Result r = Validators.jwtExpiry(jwt("{\"exp\":4102444800}"), NOW);   // 2100
        assertEquals(FindingMeta.Validation.NOT_CHECKED, r.state());
        assertTrue(r.note().contains("not expired"), r.note());
    }

    @Test void jwtWithoutExpOrNonJwtGivesNoSignal() {
        assertEquals(Validators.NONE, Validators.jwtExpiry(jwt("{\"sub\":\"x\"}"), NOW));
        assertEquals(Validators.NONE, Validators.jwtExpiry("not-a-jwt", NOW));
        assertEquals(Validators.NONE, Validators.jwtExpiry(null, NOW));
    }

    @Test void luhn() {
        assertEquals(FindingMeta.Validation.NOT_CHECKED, Validators.luhn("4242 4242 4242 4242").state());  // valid
        assertEquals(FindingMeta.Validation.INACTIVE, Validators.luhn("4242424242424241").state());         // invalid
        assertEquals(Validators.NONE, Validators.luhn("12345"));                                            // too short
    }

    @Test void regexRule() {
        Pattern p = Pattern.compile("^sk_test_");
        assertEquals(FindingMeta.Validation.INACTIVE,
                Validators.regex("sk_test_abc123", p, FindingMeta.Validation.INACTIVE, "sandbox").state());
        assertEquals(Validators.NONE, Validators.regex("sk_live_abc123", p, FindingMeta.Validation.INACTIVE, "sandbox"));
    }

    @Test void jsonLongReadsField() {
        assertEquals(1600000000L, Validators.jsonLong("{\"iat\":1,\"exp\":1600000000}", "exp"));
        assertNull(Validators.jsonLong("{\"sub\":\"x\"}", "exp"));
    }
}
