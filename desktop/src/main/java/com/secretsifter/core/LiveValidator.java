package com.secretsifter.core;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Opt-in liveness check for a detected secret, for a DEFENSIVE scanner (SecretSifter) used by
 * a team on applications it owns. It performs one read-only request to the provider's documented
 * identity/verify endpoint and maps the HTTP status to a {@link FindingMeta.Validation} state. It is
 * never invoked automatically: the operator turns live validation on (off by default) and selects
 * the providers, per the opt-in design in {@link com.secretsifter.ValidationRunner}.
 *
 * It only reports whether a credential still authenticates — it does not read, exfiltrate, or act on
 * any data behind the credential. One request, short timeout, no retries.
 */
public final class LiveValidator {

    private LiveValidator() {}

    /** How the credential is attached to the verify request for a given provider. */
    public enum Auth {
        BEARER,        // Authorization: Bearer <value>
        BASIC_USER,    // Authorization: Basic base64(value + ":")   (key as username, empty password)
        HEADER,        // a provider-specific header carries the value (header name in Endpoint detail)
        QUERY,         // value appended as a query parameter
        NONE
    }

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(8))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    /** Result of a liveness check: the state plus a short human note for the UI/report. */
    public record Result(FindingMeta.Validation state, String note) {}

    /**
     * Runs one verify request. {@code method} and {@code url} come from the resolved endpoint;
     * {@code auth} and {@code headerOrParam} say how to attach {@code credential}. Any failure to
     * reach the endpoint yields {@link FindingMeta.Validation#UNKNOWN} (inconclusive), never a false
     * "dead".
     */
    public static Result check(String method, String url, Auth auth, String headerOrParam,
                               String credential, int timeoutSeconds) {
        if (url == null || url.isBlank() || credential == null || credential.isBlank())
            return new Result(FindingMeta.Validation.UNKNOWN, "no endpoint or value");
        try {
            String finalUrl = url;
            HttpRequest.Builder rb = HttpRequest.newBuilder()
                    .timeout(Duration.ofSeconds(Math.max(1, timeoutSeconds)))
                    .header("User-Agent", "SecretSifter-validator");

            switch (auth) {
                case BEARER -> rb.header("Authorization", "Bearer " + credential);
                case BASIC_USER -> rb.header("Authorization", "Basic " +
                        java.util.Base64.getEncoder().encodeToString((credential + ":").getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                case HEADER -> rb.header(headerOrParam == null || headerOrParam.isBlank() ? "Authorization" : headerOrParam, credential);
                case QUERY -> finalUrl = url + (url.contains("?") ? "&" : "?")
                        + (headerOrParam == null || headerOrParam.isBlank() ? "key" : headerOrParam) + "="
                        + java.net.URLEncoder.encode(credential, java.nio.charset.StandardCharsets.UTF_8);
                case NONE -> { /* value already in the URL, or not required */ }
            }

            rb.uri(URI.create(finalUrl));
            if ("POST".equalsIgnoreCase(method)) rb.POST(HttpRequest.BodyPublishers.noBody());
            else if ("PUT".equalsIgnoreCase(method)) rb.PUT(HttpRequest.BodyPublishers.noBody());
            else rb.GET();

            HttpResponse<Void> resp = CLIENT.send(rb.build(), HttpResponse.BodyHandlers.discarding());
            return classify(resp.statusCode());
        } catch (java.net.http.HttpTimeoutException e) {
            return new Result(FindingMeta.Validation.UNKNOWN, "verify timed out");
        } catch (Exception e) {
            return new Result(FindingMeta.Validation.UNKNOWN, "verify unreachable: " + e.getClass().getSimpleName());
        }
    }

    /** Maps an HTTP status from a verify request to a validation state. Package-visible for tests. */
    public static Result classify(int status) {
        if (status >= 200 && status < 300)
            return new Result(FindingMeta.Validation.ACTIVE, "authenticated (HTTP " + status + ")");
        if (status == 401)
            return new Result(FindingMeta.Validation.INACTIVE, "rejected (HTTP 401)");
        if (status == 403)
            return new Result(FindingMeta.Validation.RESTRICTED, "valid but not authorized (HTTP 403)");
        if (status == 429)
            return new Result(FindingMeta.Validation.UNKNOWN, "rate-limited (HTTP 429) — inconclusive");
        if (status >= 500)
            return new Result(FindingMeta.Validation.UNKNOWN, "provider error (HTTP " + status + ") — inconclusive");
        return new Result(FindingMeta.Validation.UNKNOWN, "inconclusive (HTTP " + status + ")");
    }
}
