package com.secretscanner.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Validation endpoint reference map")
class ValidationEndpointsTest {

    @Test void publicProviderShowsFixedEndpoint() {
        assertEquals("GET https://api.github.com/user",
                ValidationEndpoints.resolve("GitHub", null));
        assertFalse(ValidationEndpoints.isSelfHosted("GitHub"));
    }

    @Test void selfHostedSubstitutesUserBaseUrl() {
        assertTrue(ValidationEndpoints.isSelfHosted("GitLab"));
        assertEquals("GET https://gitlab.yourco.com/api/v4/user",
                ValidationEndpoints.resolve("GitLab", "https://gitlab.yourco.com"));
        // trailing slash is trimmed so we never produce a double slash
        assertEquals("GET https://gitlab.yourco.com/api/v4/user",
                ValidationEndpoints.resolve("GitLab", "https://gitlab.yourco.com/"));
    }

    @Test void selfHostedWithoutBaseUrlShowsTemplateAndHint() {
        String r = ValidationEndpoints.resolve("Mattermost", null);
        assertTrue(r.contains("{base}"), r);
        assertTrue(r.toLowerCase().contains("set your base url"), r);
    }

    @Test void unknownProviderHasNoEndpoint() {
        assertEquals("", ValidationEndpoints.resolve("NoSuchProvider", null));
        assertNull(ValidationEndpoints.forProvider("NoSuchProvider"));
    }

    @Test void nonVerifiableProviderShowsReasonNotBlank() {
        // providers that can't be checked with the key alone explain why, instead of a blank cell
        String r = ValidationEndpoints.resolve("Braintree", null);   // needs key+secret pair
        assertTrue(r.startsWith("(not verifiable:"), r);
        assertFalse(ValidationEndpoints.forProvider("Braintree").verifiable());
    }

    // ── user endpoint overrides (Validation endpoints settings box) ──
    @Test void fullOverrideSetsEndpointOnANotVerifiableProvider() {
        // Z.ai is "no verify API"; a full "METHOD url" override gives it a real endpoint
        assertEquals("GET https://api.z.ai/v1/me",
                ValidationEndpoints.resolve("Z.ai", "GET https://api.z.ai/v1/me"));
    }

    @Test void fullOverrideReplacesAPublicEndpoint() {
        assertEquals("POST https://proxy.yourco.com/validate/github",
                ValidationEndpoints.resolve("GitHub", "POST https://proxy.yourco.com/validate/github"));
    }

    @Test void bareUrlOverrideOnPublicProviderBecomesGetEndpoint() {
        assertEquals("GET https://proxy.yourco.com/stripe",
                ValidationEndpoints.resolve("Stripe", "https://proxy.yourco.com/stripe"));
    }

    @Test void bareHostStillFillsSelfHostedTemplate() {
        assertEquals("GET https://gitlab.yourco.com/api/v4/user",
                ValidationEndpoints.resolve("GitLab", "https://gitlab.yourco.com"));
    }

    @Test void fullOverrideWorksForSelfHostedToo() {
        assertEquals("GET https://gl.yourco.com/custom/whoami",
                ValidationEndpoints.resolve("GitLab", "GET https://gl.yourco.com/custom/whoami"));
    }
}
