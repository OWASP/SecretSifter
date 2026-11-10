package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Proxy-level response handler — fires for ALL traffic through Burp's proxy
 * regardless of Burp's configured target scope.
 *
 * Primary role (always-on scanning):
 *   Scans every proxied response as it arrives — like JSMiner — so that anything
 *   appearing in the sitemap is automatically scanned without the user needing to
 *   configure a target scope.  Findings are injected directly via
 *   {@code api.siteMap().add(AuditIssue)} and appear immediately in
 *   Target → Site map → Issues and Dashboard → Issue Activity.
 *   For in-scope URLs where {@code SecretScanCheck.passiveAudit()} also fires,
 *   {@code consolidateIssues()} deduplicates issues with identical name+url+detail.
 *
 * Secondary role (Bulk Scan cross-origin routing):
 *   When a Bulk Scan session is running, findings for requests originating from a
 *   watched target (checked via URL, Referer, or Origin) are also routed to the
 *   Bulk Scan panel through ScopeMonitor.
 *
 * Performance:
 *   {@code handleResponseReceived()} returns {@code continueWith()} immediately;
 *   the actual scan runs on a background thread pool so the proxy pipeline is
 *   never blocked by pattern-matching work.
 *
 * This handler never modifies traffic — always returns continueWith(response).
 */
public class SecretProxyHandler implements ProxyResponseHandler {

    private final SecretScanner   scanner;
    private final ScanSettings    settings;
    private final MontoyaApi      api;
    /** Background thread pool — keeps proxy pipeline non-blocking. */
    private final ExecutorService executor;

    /** Characters of response body waiting in the scan queue; caps memory under heavy traffic. */
    private final AtomicLong queuedChars = new AtomicLong();
    private static final long MAX_QUEUED_CHARS = 256L * 1024 * 1024;
    private final AtomicLong skipped = new AtomicLong();

    public SecretProxyHandler(SecretScanner scanner, ScanSettings settings, MontoyaApi api) {
        this.scanner  = scanner;
        this.settings = settings;
        this.api      = api;
        // Fixed pool: enough threads to keep up with browsing and bulk-scan traffic, but bounded
        // so a burst of large responses cannot spawn hundreds of scanning threads. The queue is
        // bounded by total queued body size (MAX_QUEUED_CHARS), not by task count.
        int threads = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
        ThreadPoolExecutor pool = new ThreadPoolExecutor(threads, threads, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(), r -> {
                    Thread t = new Thread(r, "SecretSifter-ProxyScanner");
                    t.setDaemon(true);
                    return t;
                });
        pool.allowCoreThreadTimeOut(true);
        this.executor = pool;
    }

    /** Logs the first skip and then every 100th, so a flood of skips cannot flood the log. */
    private void logSkip(String why, String url) {
        long n = skipped.incrementAndGet();
        if (api != null && (n == 1 || n % 100 == 0))
            api.logging().logToError("[OWASP SecretSifter] proxy scan skipped (" + why + ") for "
                    + url.replaceFirst("[?#].*", "") + "; " + n + " skipped so far");
    }

    /** Called by the extension unloading handler to drain any in-flight proxy scan tasks. */
    public void shutdown() {
        executor.shutdownNow();
        try { executor.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        // Fast path: check the cheap guards synchronously on the proxy thread,
        // then hand the immutable snapshot to a background thread for scanning.
        if (!settings.isEnabled()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        var req = interceptedResponse.initiatingRequest();
        if (req == null) return ProxyResponseReceivedAction.continueWith(interceptedResponse);

        String url = req.url();
        if (url == null || url.isBlank()) return ProxyResponseReceivedAction.continueWith(interceptedResponse);

        if (settings.isExternalCdn(url)) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Eagerly extract the response body and Content-Type on the proxy thread, BEFORE
        // returning continueWith().  Burp may recycle the InterceptedResponse buffer once
        // continueWith() is returned; a background-thread call to response.bodyToString()
        // on a recycled buffer returns an empty string, and passing a stale rr to
        // api.siteMap().add() causes Burp to silently drop the AuditIssue (or NPE internally),
        // permanently losing the finding (the deduplicator already claimed the key).
        final String responseCt   = interceptedResponse.headerValue("Content-Type");
        if (ScanSettings.isBinaryMedia(responseCt)) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        if (interceptedResponse.body().length() > ScanSettings.MAX_SCAN_BYTES) {
            logSkip("body larger than " + (ScanSettings.MAX_SCAN_BYTES >> 20) + " MB", url);
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        final String responseBody = interceptedResponse.bodyToString();
        final long   bodyChars    = responseBody == null ? 0 : responseBody.length();
        if (queuedChars.addAndGet(bodyChars) > MAX_QUEUED_CHARS) {
            queuedChars.addAndGet(-bodyChars);
            logSkip("scan queue full", url);
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Deep-copy the full raw response bytes (status-line + headers + body) NOW,
        // before continueWith() is returned, so the background thread holds an immutable
        // snapshot that is safe to read after the proxy buffer is recycled.
        HttpResponse deepResponse;
        try {
            deepResponse = HttpResponse.httpResponse(interceptedResponse.toByteArray());
        } catch (Exception e) {
            deepResponse = null;
        }
        final HttpRequestResponse rr = deepResponse != null
                ? HttpRequestResponse.httpRequestResponse(req, deepResponse)
                : HttpRequestResponse.httpRequestResponse(req, interceptedResponse);

        // Submit scan to background thread — proxy pipeline is unblocked immediately.
        try {
          executor.submit(() -> {
            try {
                List<SecretFinding> findings = scanner.scanRequestResponse(rr, responseBody, responseCt);
                if (!findings.isEmpty()) {
                    // Inject into Dashboard / sitemap: one AuditIssue per (URL, rule) group
                    Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
                    for (SecretFinding f : findings)
                        grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
                    for (List<SecretFinding> group : grouped.values()) {
                        try {
                            if (SitemapDeduplicator.shouldAddProxy(group))
                                api.siteMap().add(SecretFinding.toGroupedAuditIssue(group, rr));
                        } catch (Exception ex) {
                            api.logging().logToError("[OWASP SecretSifter] siteMap.add failed for group: " + ex);
                        }
                    }

                    // Route to Bulk Scan panel when a session is active
                    if (ScopeMonitor.isActive()) {
                        String referer  = rr.request().headerValue("Referer");
                        String origin   = rr.request().headerValue("Origin");
                        String routeUrl = resolveRouteUrl(url, referer, origin);
                        if (routeUrl != null) {
                            for (SecretFinding f : findings) {
                                ScopeMonitor.notify(f, routeUrl);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                if (api != null)
                    api.logging().logToError("[OWASP SecretSifter] ProxyHandler ERROR: " + e.toString());
            } finally {
                queuedChars.addAndGet(-bodyChars);
            }
          });
        } catch (java.util.concurrent.RejectedExecutionException e) {
            queuedChars.addAndGet(-bodyChars);         // handler is shutting down
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // No interception needed on the send path
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    /**
     * Returns the URL to route findings to, or null if this request doesn't
     * belong to any watched target.
     *
     * Direct URL matching is always applied.  Cross-origin matching via Referer/Origin
     * is enabled only when ScopeMonitor.isCrossOriginFollow() is true (user opt-in via
     * the "Cross-origin APIs" checkbox).  When enabled, API calls fired by a watched
     * host's JavaScript (e.g. api.example.com called from app.example.com) are captured;
     * the trade-off is that unrelated third-party services reached from the same page
     * (e.g. analytics, CDN) may also appear in the panel.
     */
    private static String resolveRouteUrl(String url, String referer, String origin) {
        if (ScopeMonitor.isWatched(url)) return url;
        if (ScopeMonitor.isCrossOriginFollow()) {
            if (referer != null && ScopeMonitor.isWatched(referer)) return referer;
            if (origin  != null && ScopeMonitor.isWatched(origin))  return origin;
        }
        return null;
    }
}
