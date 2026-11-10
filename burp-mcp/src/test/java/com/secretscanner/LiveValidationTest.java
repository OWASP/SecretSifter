package com.secretscanner;

import com.secretscanner.core.FindingMeta;
import com.secretscanner.core.LiveValidator;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Proves live validation actually fires: a local HTTP server stands in for a provider; the validator
 * sends the credential and maps the real response to a state, both directly and end-to-end through
 * {@link ValidationRunner} with the off-by-default opt-in gate.
 */
@DisplayName("Live validation (fires against a real local endpoint)")
class LiveValidationTest {

    private static HttpServer server;
    private static int port;

    @BeforeAll static void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // only "Bearer GOODKEY" authenticates; anything else is rejected
        server.createContext("/verify", ex -> {
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            int code = "Bearer GOODKEY".equals(auth) ? 200 : 401;
            ex.sendResponseHeaders(code, -1);
            ex.close();
        });
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterAll static void stopServer() { if (server != null) server.stop(0); }

    private static String verifyUrl() { return "http://127.0.0.1:" + port + "/verify"; }

    @Test void statusMappingIsCorrect() {
        assertEquals(FindingMeta.Validation.ACTIVE,     LiveValidator.classify(200).state());
        assertEquals(FindingMeta.Validation.INACTIVE,   LiveValidator.classify(401).state());
        assertEquals(FindingMeta.Validation.RESTRICTED, LiveValidator.classify(403).state());
        assertEquals(FindingMeta.Validation.UNKNOWN,    LiveValidator.classify(429).state());
        assertEquals(FindingMeta.Validation.UNKNOWN,    LiveValidator.classify(503).state());
    }

    @Test void firesAndReportsActiveForAGoodKey() {
        LiveValidator.Result r = LiveValidator.check("GET", verifyUrl(),
                LiveValidator.Auth.BEARER, "", "GOODKEY", 5);
        assertEquals(FindingMeta.Validation.ACTIVE, r.state(), r.note());
    }

    @Test void firesAndReportsInactiveForABadKey() {
        LiveValidator.Result r = LiveValidator.check("GET", verifyUrl(),
                LiveValidator.Auth.BEARER, "", "BADKEY", 5);
        assertEquals(FindingMeta.Validation.INACTIVE, r.state(), r.note());
    }

    @Test void unreachableEndpointIsInconclusiveNotDead() {
        LiveValidator.Result r = LiveValidator.check("GET", "http://127.0.0.1:1/nope",
                LiveValidator.Auth.BEARER, "", "GOODKEY", 2);
        assertEquals(FindingMeta.Validation.UNKNOWN, r.state(), r.note());
    }

    private static SecretFinding finding(String value) {
        return SecretFinding.of("GITHUB_PAT_001", "GitHub PAT", "token", value,
                "HIGH", "FIRM", 1, "ctx", "https://app.example.test/a.js");
    }

    @Test void endToEndRespectsOptInThenFires() {
        ScanSettings s = new ScanSettings();
        s.setValidationEnabledIds(Set.of("GITHUB_PAT_001"));
        // point the GitHub check at our local server via a full endpoint override
        s.setValidationBaseUrls(List.of("GitHub = GET " + verifyUrl()));

        // off by default — live must NOT run
        SecretFinding off = ValidationRunner.validate(finding("GOODKEY"), s, 0L);
        assertEquals(FindingMeta.Validation.NOT_CHECKED, off.meta().validation(),
                "live validation must be off until the operator opts in");

        // opt in — now it fires for real
        s.setLiveValidationEnabled(true);
        SecretFinding good = ValidationRunner.validate(finding("GOODKEY"), s, 0L);
        assertEquals(FindingMeta.Validation.ACTIVE, good.meta().validation(), "good key should verify ACTIVE");
        SecretFinding bad = ValidationRunner.validate(finding("BADKEY"), s, 0L);
        assertEquals(FindingMeta.Validation.INACTIVE, bad.meta().validation(), "bad key should verify INACTIVE");
    }
}
