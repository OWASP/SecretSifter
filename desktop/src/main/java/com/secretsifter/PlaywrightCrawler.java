package com.secretsifter;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.WaitUntilState;


import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Playwright-based headless Chromium crawler for JS/JSON/XML discovery.
 *
 * Matches Python secretsauce-022926.py behaviour:
 *
 *   Per-target isolation:
 *     Each seed URL gets its own isolated BFS with scope = registrable domain of
 *     that seed only.  No cross-target contamination: scanning abc.com never
 *     captures bcdef.com resources, even if abc.com links to bcdef.com.
 *
 *   What is captured per target:
 *     - JS  (application/javascript, text/javascript, *.js / *.mjs / *.cjs)
 *     - JSON (application/json, text/json, *.json)
 *     - XML  (text/xml, application/xml, *.xml)
 *     - HTML source of each visited page (text/html)
 *
 *   Threading:
 *     Playwright Java is single-threaded.  All crawl() calls must run from one
 *     dedicated thread — BulkScanPanel uses a single-thread executor for this.
 */
public class PlaywrightCrawler {

    /** Captured resource from the browser (JS, JSON, XML, or HTML page source). */
    public record JsResult(String url, String body, String contentType, String sourcePage, String targetUrl) {}

    /** Sentinel value placed in the output queue by crawl() when all targets are done. */
    public static final JsResult END_SENTINEL = new JsResult(null, null, null, null, null);

    // ── Vendor analytics/tracking hosts to skip ───────────────────────────────
    private static final Set<String> VENDOR_HOST_DENY = Set.of(
            "www.google-analytics.com", "www.googletagmanager.com",
            "connect.facebook.net",     "static.cloudflareinsights.com",
            "challenges.cloudflare.com","www.recaptcha.net",
            "bat.bing.com",             "www.google.com",
            // ThreatMetrix / LexisNexis device fingerprinting CDN
            "h.online-metrix.net",      "online-metrix.net"
    );

    // ── Content-type hints for each capture category ──────────────────────────
    private static final List<String> JS_CT_HINTS = List.of(
            "application/javascript", "application/x-javascript",
            "text/javascript", "text/ecmascript", "application/ecmascript",
            "application/x-ecmascript", "text/js"
    );
    private static final List<String> JSON_CT_HINTS = List.of(
            "application/json", "text/json"
    );
    private static final List<String> XML_CT_HINTS = List.of(
            "text/xml", "application/xml", "application/rss+xml", "application/atom+xml"
    );

    private final String       browserPath;
    private final int          maxPages;
    private final int          maxDepth       = 3;
    private final boolean      doInteractions = true;
    private final AppLogger    logging;
    private final ScanSettings settings;
    private       CaptureStore captureStore;   // optional — populated for Details side-panel

    public PlaywrightCrawler(ScanSettings settings, AppLogger logging) {
        this.settings    = settings;
        this.browserPath = settings.getBrowserPath();
        this.maxPages    = settings.getPlaywrightMaxPages();
        this.logging     = logging;
    }

    /** Optional: attach a CaptureStore to record full request/response data for each
     *  captured URL.  The Details side-panel reads from this store. */
    public void setCaptureStore(CaptureStore store) { this.captureStore = store; }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Crawl each seed URL with a fully isolated browser context, streaming
     * captured resources into {@code outQueue} as they are discovered.
     *
     * Each seed URL is processed independently — matching Python per-target
     * isolation.  The scope for each target is limited to that target's
     * registrable domain, so abc.com never captures bcdef.com resources.
     *
     * Captured resources per target:
     *   - All JS/JSON/XML loaded during page navigation (network intercept)
     *   - Rendered HTML source of each visited page (for inline-script scanning)
     *
     * {@link #END_SENTINEL} is always placed in {@code outQueue} when this method
     * returns (even on exception), so the consumer can reliably detect end-of-stream.
     *
     * @param seedUrls     Starting URLs (one per target)
     * @param running      Checked every iteration; stops crawl when false
     * @param jsDiscovered Incremented for each capturable resource detected
     * @param jsFetched    Incremented for each unique resource body captured
     * @param outQueue     Queue into which captured resources are placed; consumer
     *                     watches for END_SENTINEL to know crawl is complete
     * @throws Exception   If Chromium binary is not installed or can't launch
     */
    public void crawl(List<String>          seedUrls,
                      AtomicBoolean          running,
                      AtomicInteger          jsDiscovered,
                      AtomicInteger          jsFetched,
                      BlockingQueue<JsResult> outQueue) throws Exception {
        if (seedUrls == null || seedUrls.isEmpty()) return;

        // Global hash dedup — avoids re-scanning identical JS chunks served by multiple targets
        Set<String> seenHashes = new HashSet<>();

        try {
        BrowserType.LaunchOptions launchOpts = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setArgs(List.of(
                        "--disable-blink-features=AutomationControlled",
                        "--disable-web-security",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--ignore-certificate-errors"
                ));
        boolean usingChromeChannel = false;
        if (!browserPath.isBlank()) {
            launchOpts.setExecutablePath(Paths.get(browserPath));
        } else if (!ChromiumInstaller.isInstalled()) {
            // Chromium not downloaded — fall back to system Edge (always present on Windows 11)
            String edgePath = ChromiumInstaller.findSystemEdge();
            if (edgePath != null) {
                logging.logToOutput("[Browser] Using system Edge: " + edgePath);
                launchOpts.setExecutablePath(Paths.get(edgePath));
            }
        } else {
            // Prefer real Google Chrome over the bundled Chromium binary.  Real Chrome
            // ships with the proprietary codecs, plugin list, and TLS fingerprint that
            // Akamai / Cloudflare bot managers expect from a "real" browser — bundled
            // Chromium is more likely to be flagged behind WAFs.  No user setup needed:
            // Playwright auto-discovers chrome.exe at the standard install path.  If
            // Chrome isn't installed, we silently fall back to bundled Chromium below.
            launchOpts.setChannel("chrome");
            usingChromeChannel = true;
        }

        // Burp loads extensions with a custom ClassLoader.  Playwright's Node.js
        // driver extraction uses getClass().getResourceAsStream() internally, which
        // fails from a non-system classloader.  Swap the context classloader temporarily.
        ClassLoader savedCL = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(PlaywrightCrawler.class.getClassLoader());

        try (Playwright playwright = Playwright.create()) {
            Browser launched;
            try {
                launched = playwright.chromium().launch(launchOpts);
            } catch (Exception ex) {
                if (usingChromeChannel) {
                    // Chrome isn't installed — drop the channel and try bundled Chromium
                    logging.logToOutput("[Browser] Real Chrome unavailable, using bundled Chromium: " + ex.getMessage());
                    launchOpts.setChannel((String) null);
                    launched = playwright.chromium().launch(launchOpts);
                } else {
                    throw ex;
                }
            }
            try (Browser browser = launched) {

                // ── Process each target independently (Python per-target isolation) ──
                for (String seed : seedUrls) {
                    if (!running.get()) break;

                    String normSeed = normaliseUrl(seed);
                    if (normSeed == null) continue;

                    // Scope = exact host of THIS seed only (Python-identical behaviour).
                    // e.g.  https://app.example.com  →  app.example.com
                    // This prevents app.example.com crawls from ever touching
                    // www.example.com, auth.example.com, or any other subdomain.
                    String targetDomain = getHostname(normSeed).toLowerCase();
                    if (targetDomain.isBlank()) continue;

                    logging.logToOutput(
                            "[Browser] ===== Target: " + normSeed +
                            "  scope=" + targetDomain + " =====");

                    // Fresh context per target for clean session/cookie isolation
                    BrowserContext context = browser.newContext(
                            new Browser.NewContextOptions()
                                    .setIgnoreHTTPSErrors(true)
                                    .setJavaScriptEnabled(true)
                                    .setBypassCSP(true)
                                    .setViewportSize(1366, 768)
                    );
                    try {
                        Deque<String[]> queue        = new ArrayDeque<>();
                        Set<String>     visitedPages = new LinkedHashSet<>();

                        queue.add(new String[]{ normSeed.split("#")[0], "0" });

                        while (!queue.isEmpty() && running.get() && visitedPages.size() < maxPages) {
                            String[] item    = queue.poll();
                            String   pageUrl = item[0];
                            int      depth   = Integer.parseInt(item[1]);

                            if (!visitedPages.add(pageUrl)) continue;
                            if (!inScope(pageUrl, targetDomain))  continue;

                            logging.logToOutput("[Browser] Visiting: " + pageUrl +
                                    "  (depth=" + depth +
                                    "  visited=" + visitedPages.size() + ")");

                            visitPage(context, pageUrl, depth, targetDomain, normSeed,
                                      queue, outQueue, seenHashes,
                                      jsDiscovered, jsFetched, running);
                        }

                        logging.logToOutput(
                                "[Browser] Target done: " + normSeed +
                                "  pages=" + visitedPages.size());
                    } finally {
                        context.close();
                    }
                }
            }
        } finally {
            Thread.currentThread().setContextClassLoader(savedCL);
        }

        logging.logToOutput("[Browser] All targets crawled. Resources queued=" + jsFetched.get());

        } finally {
            // Always signal end-of-stream so the consumer can exit cleanly,
            // even if an exception or early return interrupted the crawl.
            outQueue.offer(END_SENTINEL);
        }
    }

    // =========================================================================
    // Per-page visit
    // =========================================================================

    private void visitPage(BrowserContext          context,
                            String                  pageUrl,
                            int                     depth,
                            String                  targetDomain,
                            String                  seedUrl,
                            Deque<String[]>         queue,
                            BlockingQueue<JsResult> outQueue,
                            Set<String>             seenHashes,
                            AtomicInteger           jsDiscovered,
                            AtomicInteger           jsFetched,
                            AtomicBoolean           running) {

        // Per-page captures (accessed only from this thread — no sync needed)
        List<JsResult> pageCaptures = new ArrayList<>();
        Page page = context.newPage();

        // ── Request hook — capture headers + POST bodies BEFORE navigation ─────
        // Catches hardcoded API keys sent in custom request headers (x-api-key,
        // Authorization) and secrets embedded in POST/PUT/PATCH request bodies.
        // These are often NOT visible by scanning the JS source alone — the key
        // is assembled at runtime and only appears in network traffic.
        page.onRequest(req -> {
            if (!running.get()) return;
            try {
                String url          = req.url();
                String resourceType = req.resourceType();   // e.g. "xhr", "fetch", "script", "stylesheet", "image"
                String host         = getHostname(url).toLowerCase();
                if (VENDOR_HOST_DENY.contains(host)) return;
                if (settings.isExternalCdn(url)) return;

                // Only scan request headers for API-like resource types.
                // stylesheet / image / font / media carry the same auth headers as every
                // other request but contain no unique secrets — skipping them cuts noise.
                boolean isApiLike = "xhr".equalsIgnoreCase(resourceType)
                        || "fetch".equalsIgnoreCase(resourceType)
                        || "document".equalsIgnoreCase(resourceType)
                        || "script".equalsIgnoreCase(resourceType)
                        || "websocket".equalsIgnoreCase(resourceType);
                if (!isApiLike) return;

                // Skip binary/non-text resource URLs even when loaded via XHR/fetch.
                // Tracking pixels (clear.png), dynamically loaded CSS, and fonts share
                // the same auth headers as every other request but never carry unique secrets.
                // Strip semicolons first — ThreatMetrix appends ";CIS3SID=…" before "?".
                String urlPath = url.toLowerCase().replaceAll("[;?#].*$", "");
                if (urlPath.endsWith(".png") || urlPath.endsWith(".gif")   ||
                    urlPath.endsWith(".jpg") || urlPath.endsWith(".jpeg")  ||
                    urlPath.endsWith(".ico") || urlPath.endsWith(".webp")  ||
                    urlPath.endsWith(".svg") || urlPath.endsWith(".css")   ||
                    urlPath.endsWith(".woff")|| urlPath.endsWith(".woff2") ||
                    urlPath.endsWith(".ttf") || urlPath.endsWith(".eot")   ||
                    urlPath.endsWith(".otf") || urlPath.endsWith(".pdf")   ||
                    urlPath.endsWith(".mp4") || urlPath.endsWith(".mp3"))   return;

                // Skip device fingerprinting endpoints (ThreatMetrix / LexisNexis /fp/* pattern).
                // These URLs carry org_id= + session_id= / nonce= — distinctive ThreatMetrix shape.
                if (url.contains("/fp/") && (url.contains("org_id=") || url.contains("nonce="))) return;

                Map<String, String> hdrs = req.headers();
                String method = req.method();

                // Capture all request headers as a text blob
                if (!hdrs.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    hdrs.forEach((k, v) -> sb.append(k).append(": ").append(v).append("\n"));
                    String txt    = sb.toString();
                    byte[] tBytes = txt.getBytes(StandardCharsets.UTF_8);
                    String tHash  = sha256hex(tBytes);
                    if (seenHashes.add(tHash)) {
                        pageCaptures.add(new JsResult(
                                url + " [REQ-HEADERS]", txt, "text/plain", pageUrl, seedUrl));
                    }
                    // Always merge req-headers into the CaptureStore for the Details panel,
                    // even if hash-dedup skipped scanning — every URL the crawler sees should
                    // expose its request side to the side-panel.
                    if (captureStore != null) {
                        captureStore.merge(url, txt, null, null, null, 0, null, null, method);
                    }
                }

                // Capture POST / PUT / PATCH body
                if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) ||
                        "PATCH".equalsIgnoreCase(method)) {
                    String postData = req.postData();
                    if (postData != null && !postData.isBlank()) {
                        byte[] pBytes = postData.getBytes(StandardCharsets.UTF_8);
                        String pHash  = sha256hex(pBytes);
                        if (seenHashes.add(pHash)) {
                            String ct = hdrs.getOrDefault("content-type", "text/plain");
                            pageCaptures.add(new JsResult(
                                    url + " [REQ-BODY]", postData, ct, pageUrl, seedUrl));
                        }
                        if (captureStore != null) {
                            captureStore.merge(url, null, postData, null,
                                               hdrs.getOrDefault("content-type", null),
                                               0, null, null, method);
                        }
                    }
                }
            } catch (Exception ignored) {}
        });

        // ── Network response hook — capture JS / JSON / XML BEFORE navigation ──
        page.onResponse(resp -> {
            if (!running.get()) return;
            try {
                String url    = resp.url();
                int    status = resp.status();
                if (status < 200 || status >= 300) return;

                String host = getHostname(url).toLowerCase();
                if (VENDOR_HOST_DENY.contains(host)) return;
                if (settings.isExternalCdn(url)) return;

                // Skip device fingerprinting JS (ThreatMetrix /fp/* — same pattern as onRequest).
                // These scripts are obfuscated fingerprinting code, not app JS with secrets.
                if (url.contains("/fp/") && (url.contains("org_id=") || url.contains("nonce="))) return;

                String ct    = resp.headers().getOrDefault("content-type", "").toLowerCase();
                String urlLc = url.toLowerCase().replaceAll("[?#].*$", "");

                // resource_type == "script" catches JS files served with wrong/missing
                // content-type (e.g. text/html from JSP, application/octet-stream, etc.)
                // Mirrors Python's  is_script = resource_type == "script"  at line 8299.
                boolean isScript = "script".equalsIgnoreCase(resp.request().resourceType());

                // Determine resource category — JS, JSON, or XML
                boolean isJs   = isScript
                                  || urlLc.endsWith(".js")  || urlLc.endsWith(".mjs") || urlLc.endsWith(".cjs")
                                  || JS_CT_HINTS.stream().anyMatch(ct::contains);
                boolean isJson = urlLc.endsWith(".json")
                                  || JSON_CT_HINTS.stream().anyMatch(ct::contains);
                boolean isXml  = urlLc.endsWith(".xml")
                                  || XML_CT_HINTS.stream().anyMatch(ct::contains);

                if (!isJs && !isJson && !isXml) return;

                // JS: scope check — strict mode requires exact host; default allows same
                // registrable domain (e.g. static.example.com when scanning app.example.com).
                if (isJs) {
                    boolean inJsScope = settings.isStrictScope()
                            ? host.equalsIgnoreCase(targetDomain)
                            : extractRegistrableDomain(host).equalsIgnoreCase(extractRegistrableDomain(targetDomain));
                    if (!inJsScope) return;
                }

                // JSON/XML: only capture if the requesting page originated from the target.
                // Check the Origin / Referer request headers — if neither contains the target
                // domain this is a third-party analytics/telemetry call, not the app's API.
                // Also extract the origin/referer URL to use as the targetUrl for these resources
                // (more accurate than seedUrl since cross-origin APIs are called from a specific page).
                String jsonXmlTargetUrl = seedUrl; // default
                if (isJson || isXml) {
                    Map<String, String> reqHdrs = resp.request().headers();
                    String origin  = reqHdrs.getOrDefault("origin",  "");
                    String referer = reqHdrs.getOrDefault("referer", "");
                    String originLc  = origin.toLowerCase();
                    String refererLc = referer.toLowerCase();
                    boolean targetOriginated = originLc.contains(targetDomain.toLowerCase())
                                            || refererLc.contains(targetDomain.toLowerCase());
                    if (!targetOriginated && !settings.isFollowCrossOriginApis()) {
                        logging.logToOutput("[Browser] Skipped cross-origin " +
                                (isJson ? "JSON" : "XML") + " (no target origin/referer): " + url);
                        return;
                    }
                    // Use the Origin header as targetUrl (preferred), else Referer, else seedUrl
                    if (!origin.isBlank()) jsonXmlTargetUrl = origin;
                    else if (!referer.isBlank()) jsonXmlTargetUrl = referer;
                }

                jsDiscovered.incrementAndGet();
                String resType = isJs ? "JS" : isJson ? "JSON" : "XML";
                logging.logToOutput("[Browser] Discovered " + resType + ": " + url);
                try {
                    byte[] body = resp.body();
                    if (body != null && body.length > 0) {
                        String hash = sha256hex(body);
                        if (seenHashes.add(hash)) {
                            jsFetched.incrementAndGet();
                            String captureCt = isJs   ? "application/javascript"
                                             : isJson ? "application/json"
                                                      : "text/xml";
                            logging.logToOutput("[Browser] Captured  " + resType + ": " + url);
                            String bodyStr = new String(body, StandardCharsets.UTF_8);
                            // For JSON/XML use origin/referer-derived targetUrl; for JS use seedUrl
                            String effectiveTarget = (isJson || isXml) ? jsonXmlTargetUrl : seedUrl;
                            pageCaptures.add(new JsResult(
                                    url, bodyStr, captureCt, pageUrl, effectiveTarget));
                            // ── Stash full request+response in the CaptureStore for the
                            //    Details side-panel.  Use merge() so a prior onRequest
                            //    capture (request headers / POST body) is preserved.
                            if (captureStore != null) {
                                try {
                                    captureStore.merge(
                                            url,
                                            hdrMapToBlob(resp.request().headers()), null,
                                            bodyStr, captureCt,
                                            status, "HTTP/1.1 " + status,
                                            hdrMapToBlob(resp.headers()),
                                            resp.request().method());
                                } catch (Exception ignored) {}
                            }
                        } else {
                            logging.logToOutput("[Browser] Skipped (duplicate body): " + url);
                        }
                    }
                } catch (PlaywrightException ignored) {
                    // Response body already consumed or response aborted — skip
                }
            } catch (Exception ignored) {}
        });

        // ── Navigate ──────────────────────────────────────────────────────────
        try {
            try {
                page.navigate(pageUrl, new Page.NavigateOptions()
                        .setTimeout(30_000)
                        .setWaitUntil(WaitUntilState.NETWORKIDLE));
            } catch (PlaywrightException navErr) {
                // Fallback: domcontentloaded (less strict — still captures most JS)
                try {
                    page.navigate(pageUrl, new Page.NavigateOptions()
                            .setTimeout(30_000)
                            .setWaitUntil(WaitUntilState.DOMCONTENTLOADED));
                } catch (PlaywrightException e2) {
                    logging.logToOutput("[Browser] Nav failed: " + pageUrl + " — " + e2.getMessage());
                    page.close();
                    for (JsResult r : pageCaptures) {
                        try { outQueue.put(r); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    }
                    return;
                }
            }

            // Brief extra settle — catches deferred chunk loads
            try {
                page.waitForLoadState(LoadState.NETWORKIDLE,
                        new Page.WaitForLoadStateOptions().setTimeout(2000));
            } catch (PlaywrightException ignored) {}

            // ── Light interactions to trigger lazy-loaded JS ──────────────────
            if (doInteractions && running.get()) {
                doInteract(page);
            }

            // ── Capture rendered HTML source (Python: "scan html-viewsource") ─
            // Only capture if the page didn't redirect out of scope (e.g. to an auth portal
            // on a different host). page.url() reflects the *final* URL after all redirects.
            if (running.get()) {
                String finalUrl = page.url();
                if (inScope(finalUrl, targetDomain)) {
                    try {
                        String html = page.content();
                        if (html != null && !html.isBlank()) {
                            byte[] hBytes = html.getBytes(StandardCharsets.UTF_8);
                            String hHash  = sha256hex(hBytes);
                            if (seenHashes.add(hHash)) {
                                pageCaptures.add(new JsResult(pageUrl, html, "text/html", pageUrl, seedUrl));
                            }
                        }
                    } catch (PlaywrightException ignored) {}
                } else {
                    logging.logToOutput("[Browser] Skipped HTML (redirected out of scope to " +
                            getHostname(finalUrl) + "): " + pageUrl);
                }
            }

            // ── Capture same-host iframe / frame HTML (Python: page.frames loop) ──
            // Frameset/iframe apps (e.g. legacy enterprise portals) load all their
            // content in <frameset><frame src> — the root page is tiny with no <a>
            // links.  Each child frame is a full document with its own <script src>
            // tags.  We capture each same-host frame's HTML so SecretScanner can
            // extract inline scripts and find secrets there too.
            // We also enqueue frame URLs so the BFS visits them at depth+1, which
            // triggers the network response hook to capture their JS assets.
            if (running.get()) {
                for (Frame frame : page.frames()) {
                    if (!running.get()) break;
                    if (frame == page.mainFrame()) continue;
                    String frameUrl = frame.url();
                    if (frameUrl == null || frameUrl.isBlank()
                            || frameUrl.equals("about:blank")
                            || frameUrl.startsWith("javascript:")) continue;
                    if (!inScope(frameUrl, targetDomain)) continue;
                    try {
                        String frameHtml = frame.content();
                        if (frameHtml != null && !frameHtml.isBlank()) {
                            byte[] fBytes = frameHtml.getBytes(StandardCharsets.UTF_8);
                            String fHash  = sha256hex(fBytes);
                            if (seenHashes.add(fHash)) {
                                pageCaptures.add(new JsResult(frameUrl, frameHtml, "text/html", pageUrl, seedUrl));
                                logging.logToOutput("[Browser] Captured iframe HTML: " + frameUrl);
                            }
                            // Enqueue the frame URL so BFS visits it and its own sub-frames
                            if (depth < maxDepth) {
                                queue.add(new String[]{ frameUrl.split("#")[0], String.valueOf(depth + 1) });
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }

            // ── Extract links for BFS (only if within depth limit and still in scope) ──
            // If we were redirected out of scope (e.g. auth portal), skip BFS expansion.
            if (depth < maxDepth && running.get() && inScope(page.url(), targetDomain)) {
                enqueueLinks(page, pageUrl, depth, targetDomain, queue);
            }

        } catch (Exception e) {
            logging.logToOutput("[Browser] Page error at " + pageUrl + ": " + e.getMessage());
        } finally {
            try { page.close(); } catch (Exception ignored) {}
        }

        // Stream page captures into the output queue so the consumer can begin
        // scanning immediately while the crawler continues to the next page.
        for (JsResult r : pageCaptures) {
            try { outQueue.put(r); }
            catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    // =========================================================================
    // Interactions — gentle scroll to trigger lazy-loaded JS
    // =========================================================================

    private void doInteract(Page page) {
        try {
            page.mouse().wheel(0, 1200);
            page.waitForTimeout(400);
            page.mouse().wheel(0, 1200);
            page.waitForTimeout(400);
        } catch (Exception ignored) {}
    }

    // =========================================================================
    // BFS link extraction
    // =========================================================================

    @SuppressWarnings("unchecked")
    private void enqueueLinks(Page page, String pageUrl, int depth,
                               String targetDomain, Deque<String[]> queue) {
        // ── <a href> links ────────────────────────────────────────────────────
        try {
            List<Object> hrefs = (List<Object>) page.evalOnSelectorAll(
                    "a[href]",
                    "els => els.map(e => e.getAttribute('href'))");
            for (Object h : hrefs) {
                if (h == null) continue;
                String href = h.toString().trim();
                if (href.isBlank() || href.startsWith("javascript:") ||
                    href.startsWith("mailto:")   || href.startsWith("tel:")) continue;
                // Skip destructive links
                String lower = href.toLowerCase();
                if (lower.contains("logout") || lower.contains("signout") ||
                    lower.contains("delete") || lower.contains("remove")) continue;

                String abs = resolveUrl(pageUrl, href);
                // Only enqueue links that stay within this target's domain
                if (abs != null && inScope(abs, targetDomain)) {
                    queue.add(new String[]{ abs.split("#")[0], String.valueOf(depth + 1) });
                }
            }
        } catch (Exception ignored) {}

        // ── <frame src> / <iframe src> ────────────────────────────────────────
        // Legacy frameset apps (e.g. Korean NCRM portals) use <frameset><frame src>
        // instead of <a href> for all navigation.  Without this, the BFS finds zero
        // links and misses every JS file loaded inside the frames.
        try {
            List<Object> frameSrcs = (List<Object>) page.evalOnSelectorAll(
                    "frame[src], iframe[src]",
                    "els => els.map(e => e.getAttribute('src'))");
            for (Object s : frameSrcs) {
                if (s == null) continue;
                String src = s.toString().trim();
                if (src.isBlank() || src.startsWith("javascript:") || src.startsWith("about:")) continue;
                String abs = resolveUrl(pageUrl, src);
                if (abs != null && inScope(abs, targetDomain)) {
                    queue.add(new String[]{ abs.split("#")[0], String.valueOf(depth + 1) });
                }
            }
        } catch (Exception ignored) {}
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    private static String normaliseUrl(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String s = raw.trim();
        if (s.toLowerCase().startsWith("view-source:"))
            s = s.substring("view-source:".length()).trim();
        if (!s.startsWith("http://") && !s.startsWith("https://"))
            s = "https://" + s;
        return s;
    }

    private static String getHostname(String url) {
        if (url == null) return "";
        try { return new URL(url).getHost(); }
        catch (MalformedURLException e) { return ""; }
    }

    private static String extractRegistrableDomain(String host) {
        if (host == null || host.isBlank()) return "";
        String[] parts = host.split("\\.");
        return parts.length >= 2
                ? (parts[parts.length - 2] + "." + parts[parts.length - 1])
                : host;
    }

    /**
     * Single-target scope check — URL is in-scope only if its exact host
     * matches the seed's exact host.  Mirrors Python's  host != base_host  guard:
     *   app.example.com seed → only app.example.com URLs are followed.
     *   www.example.com, auth.example.com, etc. are all out-of-scope.
     */
    private static boolean inScope(String url, String targetDomain) {
        if (url == null || targetDomain == null || targetDomain.isBlank()) return false;
        if (!url.startsWith("http://") && !url.startsWith("https://")) return false;
        return getHostname(url).equalsIgnoreCase(targetDomain);
    }

    private static String resolveUrl(String base, String ref) {
        if (ref == null || ref.isBlank()) return null;
        if (ref.startsWith("http://") || ref.startsWith("https://")) return ref;
        try { return new URL(new URL(base), ref).toString(); }
        catch (MalformedURLException e) { return null; }
    }

    private static String sha256hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(Arrays.hashCode(data));
        }
    }

    private static String hdrMapToBlob(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        headers.forEach((k, v) -> sb.append(k).append(": ").append(v).append('\n'));
        return sb.toString();
    }
}
