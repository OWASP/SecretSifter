package com.secretsifter;

import javax.net.ssl.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Thin HTTP client that replaces Burp's {@code api.http().sendRequest()}.
 *
 * Follows up to 5 redirect hops manually (HttpClient.Redirect.NEVER) so the
 * final URL after redirects is tracked and returned — this is used by
 * BulkScanPanel to resolve relative script paths against the real app domain
 * rather than the entry-point URL that triggered the redirect chain.
 *
 * Trusts all TLS certificates — standard behaviour for a pentest tool scanning
 * targets whose certificates may be self-signed or use internal CAs.
 */
public class HttpFetcher {

    /** Result of an HTTP fetch. {@code body} may be null for auth/error responses. */
    public record FetchResult(String body, String contentType, String finalUrl, int statusCode) {}

    private final HttpClient client;
    private final AppLogger  logger;

    public HttpFetcher(AppLogger logger) {
        this.logger = logger;
        HttpClient.Builder builder = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(20));
        try {
            // Trust all certificates (self-signed, internal CA, expired, etc.)
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
            }, null);
            builder.sslContext(sc);
        } catch (Exception e) {
            logger.logToError("HttpFetcher: SSL context init failed: " + e.getMessage());
        }
        this.client = builder.build();
    }

    /**
     * Fetches {@code url}, following up to 5 redirects.
     * Returns null on network error, connection failure, or HTTP 4xx/5xx.
     */
    public FetchResult fetchUrl(String url) {
        try {
            String current = url;
            Set<String> visited = new LinkedHashSet<>();
            visited.add(current);
            HttpResponse<String> resp = null;

            for (int hop = 0; hop < 5; hop++) {
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(current))
                        .timeout(Duration.ofSeconds(30))
                        .header("User-Agent",
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                                "AppleWebKit/537.36 (KHTML, like Gecko) " +
                                "Chrome/124.0 Safari/537.36")
                        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                        .header("Accept-Language", "en-US,en;q=0.5")
                        .GET()
                        .build();

                resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                int status = resp.statusCode();

                if (status >= 300 && status < 400) {
                    String location = resp.headers().firstValue("Location").orElse(null);
                    if (location == null || location.isBlank()) break;
                    String resolved = resolveUrl(current, location);
                    if (resolved == null || !visited.add(resolved)) break;
                    current = resolved;
                } else {
                    break; // 2xx or error — stop
                }
            }

            if (resp == null) return null;
            int finalStatus = resp.statusCode();
            if (finalStatus >= 400) return new FetchResult(null, null, current, finalStatus);
            String ct = resp.headers().firstValue("Content-Type").orElse("");
            return new FetchResult(resp.body(), ct, current, finalStatus);

        } catch (Exception e) {
            logger.logToError("HttpFetcher.fetchUrl(" + url + "): " + e.getMessage());
            return null;
        }
    }

    private static String resolveUrl(String base, String ref) {
        if (ref == null || ref.isBlank()) return null;
        if (ref.startsWith("http://") || ref.startsWith("https://")) return ref;
        try { return URI.create(base).resolve(ref).toString(); }
        catch (Exception e) { return null; }
    }
}
