package com.secretsifter;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * LRU-capped in-memory store of HTTP request/response captures, keyed by URL.
 *
 * Populated by every capture point in the app (HttpFetcher, PlaywrightCrawler,
 * ProxyListener, HAR import).  The Details side-panel in BulkScanPanel queries
 * this store to display the Request / Response tabs for a selected finding.
 *
 * Memory bounds: at most {@value #MAX_ENTRIES} entries kept, each body truncated
 * to {@value #MAX_BODY_BYTES} bytes.  Access-order eviction — least-recently-viewed
 * captures are dropped first.
 */
public class CaptureStore {

    /** Immutable snapshot of a single HTTP request/response captured during scanning. */
    public record Capture(
            String url,
            String method,              // GET, POST, CONNECT, etc. — may be null
            String requestHeaders,      // "Name: Value\n..." — may be null
            String requestBody,         // may be null / truncated
            int    statusCode,          // 0 if unknown
            String statusText,          // "HTTP/1.1 200 OK" — may be null
            String responseHeaders,     // "Name: Value\n..." — may be null
            String responseBody,        // may be null / truncated
            String contentType,         // may be null
            long   timestampMs
    ) {}

    private static final int MAX_ENTRIES    = 500;
    private static final int MAX_BODY_BYTES = 2_000_000;   // 2 MB per body

    private final Map<String, Capture> map = Collections.synchronizedMap(
            new LinkedHashMap<String, Capture>(128, 0.75f, true) {
                @Override protected boolean removeEldestEntry(Map.Entry<String, Capture> e) {
                    return size() > MAX_ENTRIES;
                }
            }
    );

    public void put(Capture c) {
        if (c == null || c.url() == null) return;
        map.put(c.url(), truncate(c));
    }

    /** Convenience for callers that only have a response body + content type.  Merges
     *  with any existing entry so a richer prior capture (request headers, status, etc.)
     *  is preserved. */
    public void putResponse(String url, String contentType, String responseBody) {
        merge(url, null, null, responseBody, contentType, 0, null, null, null);
    }

    /**
     * Merge new fields into the capture for {@code url}, preserving any non-null fields
     * already present.  Use this when capture data arrives from multiple paths (e.g. the
     * Playwright onResponse hook stored full headers, then scanAndAppend is also called
     * with the response body — without merge the second call would clobber the first).
     */
    public synchronized void merge(String url,
                                    String requestHeaders, String requestBody,
                                    String responseBody, String contentType,
                                    int statusCode, String statusText,
                                    String responseHeaders, String method) {
        if (url == null) return;
        Capture e = map.get(url);
        if (e == null) {
            map.put(url, truncate(new Capture(
                    url, method, requestHeaders, requestBody,
                    statusCode, statusText, responseHeaders,
                    responseBody, contentType, System.currentTimeMillis())));
            return;
        }
        Capture merged = new Capture(
                e.url(),
                method          != null ? method          : e.method(),
                requestHeaders  != null ? requestHeaders  : e.requestHeaders(),
                requestBody     != null ? requestBody     : e.requestBody(),
                statusCode      != 0    ? statusCode      : e.statusCode(),
                statusText      != null ? statusText      : e.statusText(),
                responseHeaders != null ? responseHeaders : e.responseHeaders(),
                responseBody    != null ? responseBody    : e.responseBody(),
                contentType     != null ? contentType     : e.contentType(),
                e.timestampMs());
        map.put(url, truncate(merged));
    }

    /**
     * Look up the capture for a finding's sourceUrl.  The finding's sourceUrl often
     * carries a trailing tag like " [JS]", " [JSON]", " [REQ-HEADERS]" that must be
     * stripped for the lookup.
     */
    public Capture get(String sourceUrl) {
        if (sourceUrl == null) return null;
        Capture c = map.get(stripSuffix(sourceUrl));
        if (c == null) c = map.get(sourceUrl);   // fallback — try raw too
        return c;
    }

    public void clear() { map.clear(); }
    public int  size()  { return map.size();  }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static Capture truncate(Capture c) {
        String rb = truncBody(c.responseBody());
        String qb = truncBody(c.requestBody());
        if (rb == c.responseBody() && qb == c.requestBody()) return c;
        return new Capture(c.url(), c.method(), c.requestHeaders(), qb,
                           c.statusCode(), c.statusText(), c.responseHeaders(), rb,
                           c.contentType(), c.timestampMs());
    }

    private static String truncBody(String b) {
        if (b == null || b.length() <= MAX_BODY_BYTES) return b;
        return b.substring(0, MAX_BODY_BYTES)
             + "\n\n[... truncated by SecretSifter — original " + b.length() + " bytes ...]";
    }

    private static String stripSuffix(String sourceUrl) {
        int idx = sourceUrl.lastIndexOf(" [");
        return idx > 0 ? sourceUrl.substring(0, idx) : sourceUrl;
    }
}
