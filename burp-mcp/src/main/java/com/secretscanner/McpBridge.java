package com.secretscanner;

import burp.api.montoya.persistence.Preferences;
import com.google.gson.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

/**
 * MCP (Model Context Protocol) server for SecretSifter.
 *
 * Binds a JSON-RPC 2.0 HTTP server on 127.0.0.1:8765 so AI tools (Claude,
 * Copilot, etc.) can drive the Bulk Scan panel programmatically.
 *
 * Security controls:
 *   • Loopback-only bind — not reachable from the network
 *   • Persistent UUID auth token — saved in Burp preferences, survives restarts
 *   • Disabled by default — user must opt-in via Settings tab
 *
 * Clean unloading:
 *   stop() closes the ServerSocket and shuts down the worker pool with a
 *   2-second drain so all in-flight connections finish before the class
 *   loader is released (satisfies BApp Store criterion #6).
 */
public class McpBridge {

    static final int    PORT       = 8765;
    private static final String PATH = "/mcp";
    private static final Gson   GSON = new GsonBuilder().serializeNulls().create();

    private static final String PREF_TOKEN  = "mcp.token";
    private static final int    LOG_MAX     = 500;

    private final BulkScanPanel                      bulkPanel;
    private final ScanSettings                       settings;
    private final java.util.function.Consumer<String> logger;
    private final Preferences                        prefs;
    private volatile String                          authToken;
    /** Ring buffer — last LOG_MAX log lines emitted by this bridge and scan debug output. */
    private final ArrayDeque<String>                 logBuffer = new ArrayDeque<>();
    /** Pending cooperative triage request — set by BulkScanPanel, resolved by Claude via MCP tools. */
    private volatile java.util.concurrent.CompletableFuture<List<AiTriageProvider.TriageResult>> pendingTriageFuture;
    private volatile List<SecretFinding> pendingTriageFindings;
    private volatile ServerSocket                 serverSocket;
    private final ExecutorService                 workerPool =
            Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "SecretSifter-MCP-Worker");
                t.setDaemon(true);
                return t;
            });

    public McpBridge(BulkScanPanel bulkPanel,
                     ScanSettings settings,
                     java.util.function.Consumer<String> logger,
                     Preferences prefs) {
        this.bulkPanel = bulkPanel;
        this.settings  = settings;
        this.logger    = logger;
        this.prefs     = prefs;
        // Load persisted token; generate and save a new one on first run.
        String saved = prefs.getString(PREF_TOKEN);
        if (saved == null || saved.isBlank()) {
            saved = UUID.randomUUID().toString();
            prefs.setString(PREF_TOKEN, saved);
        }
        this.authToken = saved;
    }

    /** Returns the current auth token. */
    public String getToken() { return authToken; }

    /**
     * Generates a fresh token, persists it, and returns it.
     * Call from the EDT (Regenerate button). Claude config must be updated after this.
     */
    public String regenerateToken() {
        String newToken = UUID.randomUUID().toString();
        prefs.setString(PREF_TOKEN, newToken);
        this.authToken = newToken;
        return newToken;
    }

    // =========================================================================
    // Cooperative AI Triage (MCP provider path)
    // =========================================================================

    /**
     * Queues findings for Claude to triage via MCP.
     * BulkScanPanel calls this, then waits on the returned future.
     * Claude calls secretsifter_get_triage_request → analyzes → calls secretsifter_submit_triage_results.
     */
    public java.util.concurrent.CompletableFuture<List<AiTriageProvider.TriageResult>> enqueueTriage(List<SecretFinding> findings) {
        java.util.concurrent.CompletableFuture<List<AiTriageProvider.TriageResult>> future =
                new java.util.concurrent.CompletableFuture<>();
        pendingTriageFuture   = future;
        pendingTriageFindings = new ArrayList<>(findings);
        log("[MCP] Triage request queued: " + findings.size() + " findings — call secretsifter_get_triage_request");
        return future;
    }

    /**
     * Cancels any pending MCP triage request and unblocks the waiting future on
     * BulkScanPanel's side. Called when the user clicks "Cancel AI Triage".
     */
    public void cancelPendingTriage() {
        java.util.concurrent.CompletableFuture<List<AiTriageProvider.TriageResult>> f = pendingTriageFuture;
        pendingTriageFuture   = null;
        pendingTriageFindings = null;
        if (f != null && !f.isDone()) {
            f.completeExceptionally(new java.util.concurrent.CancellationException("user cancelled"));
            log("[MCP] Triage request cancelled by user");
        }
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    public void start() {
        if (serverSocket != null && !serverSocket.isClosed()) return;
        try {
            ServerSocket ss = new ServerSocket();
            ss.setReuseAddress(true);
            ss.bind(new InetSocketAddress("127.0.0.1", PORT));
            serverSocket = ss;

            Thread acceptor = new Thread(() -> {
                while (!ss.isClosed()) {
                    try {
                        Socket client = ss.accept();
                        client.setSoTimeout(10_000);
                        workerPool.submit(() -> handleConnection(client));
                    } catch (IOException e) {
                        if (!ss.isClosed())
                            log("[McpBridge] Accept error: " + e.getMessage());
                    }
                }
            }, "SecretSifter-MCP-Acceptor");
            acceptor.setDaemon(true);
            acceptor.start();

            log("[McpBridge] MCP server listening on http://127.0.0.1:" + PORT + PATH);
            log("[McpBridge] Auth token: " + authToken);
            log("[McpBridge] Add to ~/.claude/settings.json → mcpServers.secretsifter");
        } catch (IOException e) {
            log("[McpBridge] Failed to start: " + e.getMessage());
        }
    }

    public void stop() {
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ignored) {}
        workerPool.shutdownNow();
        try { workerPool.awaitTermination(2, TimeUnit.SECONDS); }
        catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        log("[McpBridge] MCP server stopped.");
    }

    // =========================================================================
    // HTTP / JSON-RPC dispatch
    // =========================================================================

    private void handleConnection(Socket socket) {
        try (socket;
             InputStream  in  = socket.getInputStream();
             OutputStream out = socket.getOutputStream()) {

            // --- parse request line ---
            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isBlank()) return;
            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 2) return;
            String method = parts[0].toUpperCase();
            String path   = parts[1];

            // --- parse headers ---
            Map<String, String> headers = new LinkedHashMap<>();
            String line;
            while ((line = readLine(in)) != null && !line.isBlank()) {
                int colon = line.indexOf(':');
                if (colon > 0)
                    headers.put(line.substring(0, colon).trim().toLowerCase(),
                                line.substring(colon + 1).trim());
            }

            // --- CORS pre-flight ---
            if ("OPTIONS".equals(method)) {
                writeResponse(out, 204, "No Content", "", null);
                return;
            }

            // --- GET /mcp — health probe (used by claude mcp list) ---
            if ("GET".equals(method) && PATH.equals(path)) {
                writeResponse(out, 200, "OK", "application/json",
                        "{\"server\":\"SecretSifter\",\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8));
                return;
            }

            // --- only serve POST /mcp ---
            if (!"POST".equals(method) || !PATH.equals(path)) {
                writeResponse(out, 404, "Not Found", "application/json",
                        "{\"error\":\"not found\"}".getBytes(StandardCharsets.UTF_8));
                return;
            }

            // --- auth check ---
            String auth = headers.getOrDefault("authorization", "");
            if (!auth.equals("Bearer " + authToken)) {
                writeResponse(out, 401, "Unauthorized", "application/json",
                        "{\"error\":\"invalid or missing Bearer token\"}".getBytes(StandardCharsets.UTF_8));
                return;
            }

            // --- read body ---
            int contentLength = 0;
            try { contentLength = Integer.parseInt(headers.getOrDefault("content-length", "0")); }
            catch (NumberFormatException ignored) {}
            byte[] body = new byte[Math.max(0, Math.min(contentLength, 4 * 1024 * 1024))];
            int read = 0;
            while (read < body.length) {
                int n = in.read(body, read, body.length - read);
                if (n < 0) break;
                read += n;
            }
            String bodyStr = new String(body, 0, read, StandardCharsets.UTF_8);

            // --- dispatch ---
            String responseJson = processMcp(bodyStr);
            byte[] responseBytes = responseJson.getBytes(StandardCharsets.UTF_8);
            writeResponse(out, 200, "OK", "application/json", responseBytes);

        } catch (Exception e) {
            log("[McpBridge] Connection error: " + e.getMessage());
        }
    }

    private String processMcp(String requestBody) {
        try {
            JsonObject req = GSON.fromJson(requestBody, JsonObject.class);
            if (req == null) return errorJson(null, -32700, "Parse error");

            JsonElement idEl  = req.get("id");
            String      meth  = req.has("method") ? req.get("method").getAsString() : "";
            switch (meth) {
                case "initialize":   return GSON.toJson(rpcInitialize(idEl, req));
                case "tools/list":   return GSON.toJson(rpcToolsList(idEl));
                case "tools/call":   return GSON.toJson(rpcToolsCall(req, idEl));
                default:
                    // Notifications (no id) require no response — return empty 200
                    if (meth.startsWith("notifications/")) return "{}";
                    return errorJson(idEl, -32601, "Method not found: " + meth);
            }
        } catch (Exception e) {
            return errorJson(null, -32603, "Internal error: " + e.getMessage());
        }
    }

    // =========================================================================
    // RPC handlers
    // =========================================================================

    private JsonObject rpcInitialize(JsonElement id, JsonObject req) {
        // Echo the client's requested protocol version so version negotiation succeeds.
        String clientVersion = "2025-06-18";
        try {
            JsonObject params = req.getAsJsonObject("params");
            if (params != null && params.has("protocolVersion"))
                clientVersion = params.get("protocolVersion").getAsString();
        } catch (Exception ignored) {}

        JsonObject caps     = new JsonObject();
        JsonObject toolsCap = new JsonObject();
        caps.add("tools", toolsCap);
        JsonObject serverInfo = new JsonObject();
        serverInfo.addProperty("name", "SecretSifter");
        serverInfo.addProperty("version", "1.2.3");
        JsonObject result = new JsonObject();
        result.addProperty("protocolVersion", clientVersion);
        result.add("serverInfo", serverInfo);
        result.add("capabilities", caps);
        return buildResult(id, result);
    }

    private JsonObject rpcToolsList(JsonElement id) {
        JsonArray tools = new JsonArray();
        tools.add(makeTool("secretsifter_start_bulk_scan",
                "Populate the Bulk Scan tab with target URLs, configure tier/headless/debug options, and start the scan. Poll secretsifter_get_scan_status for progress.",
                startScanSchema()));
        tools.add(makeTool("secretsifter_get_scan_status",
                "Return the current scan state: running flag, URLs done vs expected, findings count, scanned/failed counters.",
                emptySchema()));
        tools.add(makeTool("secretsifter_get_findings",
                "Return all current findings as a JSON array. Optionally filter by severity.",
                getFindingsSchema()));
        tools.add(makeTool("secretsifter_get_target_status",
                "Return the per-target scan status table: each URL with its status icon and detail message.",
                emptySchema()));
        tools.add(makeTool("secretsifter_export_report",
                "Export findings to a file. Supported formats: html, csv, json, zip.",
                exportSchema()));
        tools.add(makeTool("secretsifter_cancel_scan",
                "Stop the currently running bulk scan.",
                emptySchema()));
        tools.add(makeTool("secretsifter_clear_results",
                "Clear all findings and reset the results table.",
                emptySchema()));
        tools.add(makeTool("secretsifter_update_finding_severity",
                "Update the severity (and optionally confidence) of a specific finding row. Use the row number from the # column (1-based).",
                updateSeveritySchema()));
        tools.add(makeTool("secretsifter_delete_finding",
                "Delete one or more findings from the dashboard by their # column row numbers. Without confirmed=true the tool returns a preview; set confirmed=true to execute the deletion.",
                deleteFindingSchema()));
        tools.add(makeTool("secretsifter_get_settings",
                "Return all current scanner settings: tier, entropy threshold, PII toggle, CDN blocklist, key blocklist/allowlist, and custom rules.",
                emptySchema()));
        tools.add(makeTool("secretsifter_update_settings",
                "Update one or more scanner settings and persist them. Omit any parameter to leave its current value unchanged.",
                updateSettingsSchema()));
        tools.add(makeTool("secretsifter_get_custom_rules",
                "Return custom regex rules defined by the user. Format: 'RuleName | regex | SEVERITY' per line.",
                emptySchema()));
        tools.add(makeTool("secretsifter_set_custom_rules",
                "Replace the custom regex rule list. Pass an array of rule strings in format 'RuleName | regex | SEVERITY'. Optionally toggle custom rules on/off.",
                setCustomRulesSchema()));
        tools.add(makeTool("secretsifter_get_logs",
                "Return recent extension log entries: MCP bridge events and suppressed-findings debug log from the last scan.",
                getLogsSchema()));
        tools.add(makeTool("secretsifter_get_triage_request",
                "Return the pending AI triage request: a JSON array of findings queued by the 'AI Triage All (MCP)' button. Returns empty if no request is pending.",
                emptySchema()));
        tools.add(makeTool("secretsifter_submit_triage_results",
                "Submit triage results for a pending request. Pass a JSON array matching the format returned by secretsifter_get_triage_request, with 'real', 'severity', 'confidence', and 'reasoning' fields per finding.",
                submitTriageSchema()));
        JsonObject result = new JsonObject();
        result.add("tools", tools);
        return buildResult(id, result);
    }

    private JsonObject rpcToolsCall(JsonObject req, JsonElement id) {
        JsonElement paramsEl = req.get("params");
        if (paramsEl == null || !paramsEl.isJsonObject())
            return buildError(id, -32602, "'params' object required");
        JsonObject params   = paramsEl.getAsJsonObject();
        String     toolName = params.has("name") ? params.get("name").getAsString() : "";
        JsonObject args     = params.has("arguments") && params.get("arguments").isJsonObject()
                ? params.getAsJsonObject("arguments") : new JsonObject();
        try {
            String text;
            switch (toolName) {
                case "secretsifter_start_bulk_scan":      text = toolStartScan(args);           break;
                case "secretsifter_get_scan_status":      text = toolGetStatus();               break;
                case "secretsifter_get_findings":         text = toolGetFindings(args);         break;
                case "secretsifter_get_target_status":    text = toolGetTargetStatus();         break;
                case "secretsifter_export_report":        text = toolExportReport(args);        break;
                case "secretsifter_cancel_scan":          text = toolCancelScan();              break;
                case "secretsifter_clear_results":        text = toolClearResults();            break;
                case "secretsifter_update_finding_severity": text = toolUpdateSeverity(args);      break;
                case "secretsifter_delete_finding":          text = toolDeleteFinding(args);       break;
                case "secretsifter_get_settings":            text = toolGetSettings();             break;
                case "secretsifter_update_settings":         text = toolUpdateSettings(args);      break;
                case "secretsifter_get_custom_rules":        text = toolGetCustomRules();          break;
                case "secretsifter_set_custom_rules":        text = toolSetCustomRules(args);      break;
                case "secretsifter_get_logs":                text = toolGetLogs(args);             break;
                case "secretsifter_get_triage_request":      text = toolGetTriageRequest();         break;
                case "secretsifter_submit_triage_results":   text = toolSubmitTriageResults(args);  break;
                default: return buildError(id, -32601, "Unknown tool: " + toolName);
            }
            return buildResult(id, textContent(text));
        } catch (Exception e) {
            return buildError(id, -32603, e.getMessage());
        }
    }

    // =========================================================================
    // Tool implementations
    // =========================================================================

    private String toolStartScan(JsonObject args) throws Exception {
        if (!args.has("urls"))
            throw new IllegalArgumentException("'urls' is required");
        JsonElement urlsEl = args.get("urls");
        List<String> urls = new ArrayList<>();
        if (urlsEl.isJsonArray()) {
            for (JsonElement e : urlsEl.getAsJsonArray())
                urls.add(e.getAsString().trim());
        } else {
            for (String u : urlsEl.getAsString().split("\n"))
                if (!u.isBlank()) urls.add(u.trim());
        }
        if (urls.isEmpty())
            throw new IllegalArgumentException("'urls' must not be empty");

        String  tier     = args.has("tier")     ? args.get("tier").getAsString().toUpperCase()  : "FULL";
        boolean headless = args.has("headless") && args.get("headless").getAsBoolean();
        boolean debug    = args.has("debug")    && args.get("debug").getAsBoolean();

        bulkPanel.startScanProgrammatic(urls, tier, headless, debug);
        return String.format("Scan started: %d URL(s) | Tier=%s | Headless=%b | Debug=%b",
                urls.size(), tier, headless, debug);
    }

    private String toolGetStatus() {
        BulkScanPanel.ScanStatus s = bulkPanel.getScanStatus();
        int pct = s.totalExpected > 0
                ? (int) (100.0 * s.urlsDone / s.totalExpected) : (s.running ? 0 : 100);
        JsonObject o = new JsonObject();
        o.addProperty("running",         s.running);
        o.addProperty("urlsDone",        s.urlsDone);
        o.addProperty("totalExpected",   s.totalExpected);
        o.addProperty("progressPercent", pct);
        o.addProperty("scanned",         s.scanned);
        o.addProperty("failed",          s.failed);
        o.addProperty("findingsCount",   s.findingsCount);
        return GSON.toJson(o);
    }

    private String toolGetFindings(JsonObject args) {
        String filter = args.has("severity_filter")
                ? args.get("severity_filter").getAsString().toUpperCase() : null;
        List<SecretFinding> findings = bulkPanel.getFindings();
        JsonArray arr = new JsonArray();
        for (SecretFinding f : findings) {
            if (filter != null && !filter.equals(f.severity().toUpperCase())) continue;
            JsonObject o = new JsonObject();
            o.addProperty("ruleId",      nvl(f.ruleId()));
            o.addProperty("ruleName",    nvl(f.ruleName()));
            o.addProperty("keyName",     nvl(f.keyName()));
            o.addProperty("value",       nvl(f.matchedValue()));
            o.addProperty("severity",    nvl(f.severity()));
            o.addProperty("confidence",  nvl(f.confidence()));
            o.addProperty("url",         nvl(f.sourceUrl()));
            o.addProperty("targetUrl",   nvl(f.targetUrl()));
            o.addProperty("lineNumber",  f.lineNumber());
            o.addProperty("context",     nvl(f.context()));
            arr.add(o);
        }
        return GSON.toJson(arr);
    }

    private String toolGetTargetStatus() {
        List<String[]> rows = bulkPanel.getTargetStatusRows();
        JsonArray arr = new JsonArray();
        for (String[] row : rows) {
            JsonObject o = new JsonObject();
            o.addProperty("status",    row.length > 0 ? nvl(row[0]) : "");
            o.addProperty("targetUrl", row.length > 1 ? nvl(row[1]) : "");
            o.addProperty("detail",    row.length > 2 ? nvl(row[2]) : "");
            arr.add(o);
        }
        return GSON.toJson(arr);
    }

    private String toolExportReport(JsonObject args) throws Exception {
        String format = args.has("format") ? args.get("format").getAsString().toLowerCase() : "html";
        List<SecretFinding> findings = bulkPanel.getFindings();
        if (findings.isEmpty()) return "No findings to export.";

        String ts   = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        Path   dest = Paths.get(System.getProperty("user.home"),
                "secretsifter_report_" + ts + "." + (format.equals("zip") ? "zip" : format));

        switch (format) {
            case "csv":  writeCsv(findings, dest);  break;
            case "json": writeJson(findings, dest); break;
            case "zip":  writeZip(findings, ts, dest); break;
            default:     writeHtml(findings, dest); break;
        }
        return "Exported " + findings.size() + " finding(s) to: " + dest;
    }

    private String toolCancelScan() {
        bulkPanel.stopScan();
        return "Scan cancelled.";
    }

    private String toolClearResults() throws Exception {
        bulkPanel.clearResultsProgrammatic();
        return "Results cleared.";
    }

    private String toolUpdateSeverity(JsonObject args) throws Exception {
        if (!args.has("row"))
            throw new IllegalArgumentException("'row' is required (1-based # from the findings table)");
        if (!args.has("severity"))
            throw new IllegalArgumentException("'severity' is required");
        int    row      = args.get("row").getAsInt();
        String severity = args.get("severity").getAsString().toUpperCase();
        String conf     = args.has("confidence") ? args.get("confidence").getAsString().toUpperCase() : null;

        Set<String> validSev = Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION");
        if (!validSev.contains(severity))
            throw new IllegalArgumentException(
                    "Invalid severity: " + severity + ". Use CRITICAL, HIGH, MEDIUM, LOW, or INFORMATION.");

        final boolean[] ok = {false};
        javax.swing.SwingUtilities.invokeAndWait(() ->
                ok[0] = bulkPanel.updateFindingByNum(row, severity, conf));
        if (!ok[0])
            throw new IllegalArgumentException(
                    "Row " + row + " not found (table currently has "
                    + bulkPanel.getFindings().size() + " row(s)).");

        return String.format("Row %d updated — severity: %s%s",
                row, severity, conf != null ? "  confidence: " + conf : "");
    }

    private String toolDeleteFinding(JsonObject args) throws Exception {
        boolean confirmed = args.has("confirmed") && args.get("confirmed").getAsBoolean();

        // Collect row numbers (single int or array)
        List<Integer> rows = new ArrayList<>();
        if (args.has("rows") && args.get("rows").isJsonArray()) {
            for (JsonElement e : args.getAsJsonArray("rows")) rows.add(e.getAsInt());
        } else if (args.has("row")) {
            rows.add(args.get("row").getAsInt());
        } else {
            throw new IllegalArgumentException("'row' or 'rows' is required");
        }

        if (!confirmed) {
            return "Will delete " + rows.size() + " finding(s): rows " + rows
                    + ". Call again with confirmed=true to proceed.";
        }

        // Perform deletions from highest row# to lowest to avoid index shifting
        List<Integer> sorted = new ArrayList<>(rows);
        sorted.sort(Collections.reverseOrder());
        List<String> deleted = new ArrayList<>();
        for (int rowNum : sorted) {
            final int rn = rowNum;
            final String[] desc = {null};
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                SecretFinding f = bulkPanel.deleteFindingByNum(rn);
                if (f != null)
                    desc[0] = "Row #" + rn + ": " + f.ruleName() + " / " + f.keyName()
                            + " @ " + f.sourceUrl();
            });
            if (desc[0] != null) deleted.add(desc[0]);
            else deleted.add("Row #" + rowNum + ": not found");
        }
        return "Deleted " + deleted.size() + " finding(s):\n" + String.join("\n", deleted);
    }

    private String toolGetSettings() {
        JsonObject o = new JsonObject();
        o.addProperty("enabled",             settings.isEnabled());
        o.addProperty("tier",                settings.getTier().name());
        o.addProperty("entropyThreshold",    settings.getEntropyThreshold());
        o.addProperty("piiEnabled",          settings.isPiiEnabled());
        o.addProperty("scanRequestsEnabled", settings.isScanRequestsEnabled());
        o.addProperty("allowInsecureSsl",    settings.isAllowInsecureSsl());
        o.addProperty("customRulesEnabled",  settings.isCustomRulesEnabled());
        JsonArray cdn = new JsonArray();  settings.getCdnBlocklist().forEach(cdn::add);
        JsonArray kb  = new JsonArray();  settings.getKeyBlocklist().forEach(kb::add);
        JsonArray ka  = new JsonArray();  settings.getKeyAllowlist().forEach(ka::add);
        JsonArray cr  = new JsonArray();  settings.getCustomRules().forEach(cr::add);
        o.add("cdnBlocklist",  cdn);
        o.add("keyBlocklist",  kb);
        o.add("keyAllowlist",  ka);
        o.add("customRules",   cr);
        return GSON.toJson(o);
    }

    private String toolUpdateSettings(JsonObject args) {
        StringBuilder changes = new StringBuilder();
        if (args.has("enabled")) {
            boolean v = args.get("enabled").getAsBoolean();
            settings.setEnabled(v);
            changes.append("enabled=").append(v).append(' ');
        }
        if (args.has("tier")) {
            String v = args.get("tier").getAsString().toUpperCase();
            settings.setTier(ScanSettings.ScanTier.valueOf(v));
            changes.append("tier=").append(v).append(' ');
        }
        if (args.has("entropy_threshold")) {
            double v = args.get("entropy_threshold").getAsDouble();
            settings.setEntropyThreshold(v);
            changes.append("entropyThreshold=").append(v).append(' ');
        }
        if (args.has("pii_enabled")) {
            boolean v = args.get("pii_enabled").getAsBoolean();
            settings.setPiiEnabled(v);
            changes.append("piiEnabled=").append(v).append(' ');
        }
        if (args.has("scan_requests_enabled")) {
            boolean v = args.get("scan_requests_enabled").getAsBoolean();
            settings.setScanRequestsEnabled(v);
            changes.append("scanRequestsEnabled=").append(v).append(' ');
        }
        if (args.has("custom_rules_enabled")) {
            boolean v = args.get("custom_rules_enabled").getAsBoolean();
            settings.setCustomRulesEnabled(v);
            changes.append("customRulesEnabled=").append(v).append(' ');
        }
        if (args.has("cdn_blocklist") && args.get("cdn_blocklist").isJsonArray()) {
            List<String> list = new ArrayList<>();
            args.getAsJsonArray("cdn_blocklist").forEach(e -> list.add(e.getAsString()));
            settings.setCdnBlocklist(list);
            changes.append("cdnBlocklist(").append(list.size()).append(" entries) ");
        }
        if (args.has("key_blocklist") && args.get("key_blocklist").isJsonArray()) {
            List<String> list = new ArrayList<>();
            args.getAsJsonArray("key_blocklist").forEach(e -> list.add(e.getAsString()));
            settings.setKeyBlocklist(list);
            changes.append("keyBlocklist(").append(list.size()).append(" entries) ");
        }
        if (args.has("key_allowlist") && args.get("key_allowlist").isJsonArray()) {
            List<String> list = new ArrayList<>();
            args.getAsJsonArray("key_allowlist").forEach(e -> list.add(e.getAsString()));
            settings.setKeyAllowlist(list);
            changes.append("keyAllowlist(").append(list.size()).append(" entries) ");
        }
        if (changes.length() == 0) return "No settings changed.";
        settings.saveToPreferences(prefs);
        return "Settings updated: " + changes.toString().trim();
    }

    private String toolGetCustomRules() {
        List<String> rules = settings.getCustomRules();
        if (rules.isEmpty()) return "No custom rules defined.";
        JsonArray arr = new JsonArray();
        rules.forEach(arr::add);
        JsonObject o = new JsonObject();
        o.addProperty("enabled", settings.isCustomRulesEnabled());
        o.add("rules", arr);
        o.addProperty("count", rules.size());
        o.addProperty("format", "RuleName | regex | SEVERITY  (SEVERITY: CRITICAL/HIGH/MEDIUM/LOW/INFORMATION)");
        return GSON.toJson(o);
    }

    private String toolSetCustomRules(JsonObject args) {
        if (!args.has("rules"))
            throw new IllegalArgumentException("'rules' array is required");
        List<String> newRules = new ArrayList<>();
        for (JsonElement e : args.getAsJsonArray("rules")) {
            String line = e.getAsString().trim();
            if (!line.isEmpty()) newRules.add(line);
        }
        settings.setCustomRules(newRules);
        if (args.has("enabled"))
            settings.setCustomRulesEnabled(args.get("enabled").getAsBoolean());
        settings.saveToPreferences(prefs);
        return String.format("Custom rules updated: %d rule(s) saved, enabled=%b",
                newRules.size(), settings.isCustomRulesEnabled());
    }

    private String toolGetLogs(JsonObject args) {
        int count = args.has("count") ? Math.min(args.get("count").getAsInt(), LOG_MAX) : 100;
        List<String> out = new ArrayList<>();
        synchronized (logBuffer) {
            List<String> buf = new ArrayList<>(logBuffer);
            int start = Math.max(0, buf.size() - count);
            out.addAll(buf.subList(start, buf.size()));
        }
        // Also append scan debug log if budget remains
        int remaining = count - out.size();
        if (remaining > 0) {
            List<String> dbg = bulkPanel.getDebugLog(remaining);
            if (!dbg.isEmpty()) {
                out.add("--- scan debug log (suppressed findings) ---");
                out.addAll(dbg);
            }
        }
        if (out.isEmpty()) return "No log entries available.";
        return String.join("\n", out);
    }

    private String toolGetTriageRequest() {
        List<SecretFinding> findings = pendingTriageFindings;
        if (findings == null || findings.isEmpty())
            return "No pending triage request. Click 'AI Triage All' in SecretSifter with MCP provider selected first.";
        JsonArray arr = new JsonArray();
        for (int i = 0; i < findings.size(); i++) {
            SecretFinding f = findings.get(i);
            JsonObject o = new JsonObject();
            o.addProperty("id",      i + 1);
            o.addProperty("rule",    f.ruleId() != null ? f.ruleId() : f.ruleName());
            o.addProperty("key",     f.keyName() != null ? f.keyName() : "");
            String val = f.matchedValue() != null ? f.matchedValue() : "";
            o.addProperty("value",   val.length() > 60 ? val.substring(0, 57) + "..." : val);
            String ctx = f.context() != null ? f.context().replace("\n", " ").strip() : "";
            if (!ctx.isEmpty()) o.addProperty("context", ctx.length() > 100 ? ctx.substring(0, 97) + "..." : ctx);
            o.addProperty("url",     f.sourceUrl() != null ? f.sourceUrl() : "");
            o.addProperty("severity",   f.severity());
            o.addProperty("confidence", f.confidence());
            arr.add(o);
        }
        return "Triage " + findings.size() + " findings. For each, set real=true/false, severity, confidence, reasoning.\n" +
               "Then call secretsifter_submit_triage_results with a 'results' JSON array.\n\n" +
               "FINDINGS:\n" + GSON.toJson(arr);
    }

    private String toolSubmitTriageResults(JsonObject args) {
        java.util.concurrent.CompletableFuture<List<AiTriageProvider.TriageResult>> future = pendingTriageFuture;
        if (future == null || future.isDone())
            return "No pending triage request to complete. Call secretsifter_get_triage_request first.";
        if (!args.has("results"))
            throw new IllegalArgumentException("'results' array is required");
        JsonArray arr = args.getAsJsonArray("results");
        Map<Integer, AiTriageProvider.TriageResult> byId = new LinkedHashMap<>();
        for (JsonElement el : arr) {
            JsonObject o   = el.getAsJsonObject();
            int id         = o.has("id")         ? o.get("id").getAsInt()         : 0;
            boolean real   = !o.has("real")      || o.get("real").getAsBoolean();
            String sev     = o.has("severity")   ? o.get("severity").getAsString()   : "MEDIUM";
            String conf    = o.has("confidence") ? o.get("confidence").getAsString() : "FIRM";
            String reason  = o.has("reasoning")  ? o.get("reasoning").getAsString()  : "";
            byId.put(id, new AiTriageProvider.TriageResult(real,
                    AiTriageProvider.normalSev(sev), AiTriageProvider.normalConf(conf), reason));
        }
        int count = pendingTriageFindings != null ? pendingTriageFindings.size() : byId.size();
        List<AiTriageProvider.TriageResult> results = new ArrayList<>();
        for (int i = 1; i <= count; i++)
            results.add(byId.getOrDefault(i, new AiTriageProvider.TriageResult(true, "MEDIUM", "FIRM", "No response")));
        pendingTriageFindings = null;
        pendingTriageFuture   = null;
        future.complete(results);
        log("[MCP] Triage results submitted: " + results.size() + " findings processed.");
        return "Triage results submitted: " + results.size() + " finding(s) processed. SecretSifter will update the table.";
    }

    // =========================================================================
    // Export helpers
    // =========================================================================

    private void writeCsv(List<SecretFinding> findings, Path dest) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("Rule ID,Rule Name,Key,Value,Severity,Confidence,URL,Target URL,Line\n");
        for (SecretFinding f : findings) {
            sb.append(csvEsc(f.ruleId())).append(',')
              .append(csvEsc(f.ruleName())).append(',')
              .append(csvEsc(f.keyName())).append(',')
              .append(csvEsc(f.matchedValue())).append(',')
              .append(csvEsc(f.severity())).append(',')
              .append(csvEsc(f.confidence())).append(',')
              .append(csvEsc(f.sourceUrl())).append(',')
              .append(csvEsc(nvl(f.targetUrl()))).append(',')
              .append(f.lineNumber()).append('\n');
        }
        Files.writeString(dest, sb.toString(), StandardCharsets.UTF_8);
    }

    private void writeJson(List<SecretFinding> findings, Path dest) throws IOException {
        Files.writeString(dest,
                GSON.toJson(GSON.fromJson(toolGetFindings(new JsonObject()), JsonArray.class)),
                StandardCharsets.UTF_8);
    }

    private void writeHtml(List<SecretFinding> findings, Path dest) throws IOException {
        // Pass null for the target parameter so the report header omits the "Target: …" segment.
        // Previously this passed the filename, which rendered as "Target: secretsifter_2026-04-25.html"
        // — a filename, not a target domain. Per-domain reports correctly populate the target via
        // HtmlReportGenerator.generatePerDomain.
        String html = HtmlReportGenerator.generate(findings, null, "html");
        Files.writeString(dest, html, StandardCharsets.UTF_8);
    }

    private void writeZip(List<SecretFinding> findings, String ts, Path dest) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(dest))) {
            // Pass null for the target so the report header has no "Target: <date>" line.
            // The previous code passed `ts` (timestamp) which surfaced as a date in the target field.
            addZipEntry(zos, "secretsifter_" + ts + ".html",
                    HtmlReportGenerator.generate(findings, null, "html")
                            .getBytes(StandardCharsets.UTF_8));
            String csvName = "secretsifter_findings_" + ts + ".csv";
            Path tmp = Files.createTempFile("ss_csv_", ".csv");
            writeCsv(findings, tmp);
            addZipEntry(zos, csvName, Files.readAllBytes(tmp));
            Files.deleteIfExists(tmp);
        }
    }

    private static void addZipEntry(ZipOutputStream zos, String name, byte[] data)
            throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(data);
        zos.closeEntry();
    }

    // =========================================================================
    // HTTP helpers
    // =========================================================================

    private String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) >= 0) {
            if (b == '\n') break;
            if (b != '\r') sb.append((char) b);
        }
        return sb.toString();
    }

    private void writeResponse(OutputStream out, int status, String statusText,
                                String contentType, byte[] body) throws IOException {
        byte[] b = (body != null) ? body : new byte[0];
        String headers =
                "HTTP/1.1 " + status + " " + statusText + "\r\n" +
                "Access-Control-Allow-Origin: *\r\n" +
                "Access-Control-Allow-Methods: POST, OPTIONS\r\n" +
                "Access-Control-Allow-Headers: Content-Type, Authorization\r\n" +
                (contentType.isEmpty() ? "" : "Content-Type: " + contentType + "\r\n") +
                "Content-Length: " + b.length + "\r\n" +
                "Connection: close\r\n\r\n";
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        if (b.length > 0) out.write(b);
        out.flush();
    }

    // =========================================================================
    // JSON-RPC builder helpers
    // =========================================================================

    private JsonObject buildResult(JsonElement id, JsonElement result) {
        JsonObject o = new JsonObject();
        o.addProperty("jsonrpc", "2.0");
        o.add("id", id);
        o.add("result", result);
        return o;
    }

    private JsonObject buildError(JsonElement id, int code, String message) {
        JsonObject err = new JsonObject();
        err.addProperty("code",    code);
        err.addProperty("message", message);
        JsonObject o = new JsonObject();
        o.addProperty("jsonrpc", "2.0");
        o.add("id",    id);
        o.add("error", err);
        return o;
    }

    private String errorJson(JsonElement id, int code, String message) {
        return GSON.toJson(buildError(id, code, message));
    }

    private JsonObject textContent(String text) {
        JsonArray content = new JsonArray();
        JsonObject item   = new JsonObject();
        item.addProperty("type", "text");
        item.addProperty("text", text);
        content.add(item);
        JsonObject result = new JsonObject();
        result.add("content", content);
        return result;
    }

    private JsonObject makeTool(String name, String description, JsonObject inputSchema) {
        JsonObject tool = new JsonObject();
        tool.addProperty("name",        name);
        tool.addProperty("description", description);
        tool.add("inputSchema",         inputSchema);
        return tool;
    }

    // =========================================================================
    // Schema builders
    // =========================================================================

    private JsonObject startScanSchema() {
        JsonObject props = new JsonObject();
        JsonObject urls  = new JsonObject();
        urls.addProperty("type",        "array");
        urls.addProperty("description", "List of target URLs to scan");
        JsonObject urlItems = new JsonObject(); urlItems.addProperty("type", "string");
        urls.add("items", urlItems);
        props.add("urls", urls);
        addStringProp(props, "tier",     "Scan tier: FAST, LIGHT, or FULL (default FULL)");
        addBoolProp  (props, "headless", "Launch headless Chrome to capture dynamic XHR/fetch calls");
        addBoolProp  (props, "debug",    "Enable debug logging to Burp Extensions > Output");
        return buildSchema(props, List.of("urls"));
    }

    private JsonObject getFindingsSchema() {
        JsonObject props = new JsonObject();
        addStringProp(props, "severity_filter",
                "Optional: return only findings of this severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATION)");
        return buildSchema(props, List.of());
    }

    private JsonObject exportSchema() {
        JsonObject props = new JsonObject();
        addStringProp(props, "format",
                "Export format: html (default), csv, json, or zip");
        return buildSchema(props, List.of());
    }

    private JsonObject updateSeveritySchema() {
        JsonObject props = new JsonObject();
        addIntProp   (props, "row",        "1-based row number from the # column in the findings table");
        addStringProp(props, "severity",   "New severity: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATION");
        addStringProp(props, "confidence", "Optional: new confidence to set (CERTAIN, FIRM, TENTATIVE)");
        return buildSchema(props, List.of("row", "severity"));
    }

    private JsonObject deleteFindingSchema() {
        JsonObject props = new JsonObject();
        addIntProp  (props, "row",       "Single row # to delete (use 'rows' for multiple)");
        JsonObject rowsP = new JsonObject();
        rowsP.addProperty("type", "array");
        rowsP.addProperty("description", "Array of row # values to delete");
        JsonObject items = new JsonObject(); items.addProperty("type", "integer");
        rowsP.add("items", items);
        props.add("rows", rowsP);
        addBoolProp (props, "confirmed", "Must be true to execute deletion; omit for a preview");
        return buildSchema(props, List.of());
    }

    private JsonObject updateSettingsSchema() {
        JsonObject props = new JsonObject();
        addBoolProp  (props, "enabled",              "Enable or disable all scanning");
        addStringProp(props, "tier",                 "Scan tier: FAST, LIGHT, or FULL");
        JsonObject ep = new JsonObject();
        ep.addProperty("type",        "number");
        ep.addProperty("description", "Shannon entropy threshold (0.0–8.0, default 3.5)");
        props.add("entropy_threshold", ep);
        addBoolProp  (props, "pii_enabled",           "Enable PII detection rules");
        addBoolProp  (props, "scan_requests_enabled", "Scan request headers/body as well as responses");
        addBoolProp  (props, "custom_rules_enabled",  "Enable/disable user-defined custom rules");
        JsonObject listProp = new JsonObject();
        listProp.addProperty("type", "array");
        listProp.addProperty("description", "Replace the CDN blocklist (array of domain strings)");
        JsonObject strItem = new JsonObject(); strItem.addProperty("type", "string");
        listProp.add("items", strItem);
        props.add("cdn_blocklist", listProp);
        JsonObject kbp = new JsonObject();
        kbp.addProperty("type", "array");
        kbp.addProperty("description", "Replace the key-name blocklist");
        kbp.add("items", strItem);
        props.add("key_blocklist", kbp);
        JsonObject kap = new JsonObject();
        kap.addProperty("type", "array");
        kap.addProperty("description", "Replace the key-name allowlist (force-include these keys)");
        kap.add("items", strItem);
        props.add("key_allowlist", kap);
        return buildSchema(props, List.of());
    }

    private JsonObject setCustomRulesSchema() {
        JsonObject props = new JsonObject();
        JsonObject rulesProp = new JsonObject();
        rulesProp.addProperty("type", "array");
        rulesProp.addProperty("description",
                "Array of rule strings: 'RuleName | regex | SEVERITY'");
        JsonObject strItem = new JsonObject(); strItem.addProperty("type", "string");
        rulesProp.add("items", strItem);
        props.add("rules", rulesProp);
        addBoolProp(props, "enabled", "Optional: enable or disable all custom rules");
        return buildSchema(props, List.of("rules"));
    }

    private JsonObject getLogsSchema() {
        JsonObject props = new JsonObject();
        addIntProp(props, "count", "Max number of log lines to return (default 100, max 500)");
        return buildSchema(props, List.of());
    }

    private JsonObject submitTriageSchema() {
        JsonObject props = new JsonObject();
        JsonObject resultsDesc = new JsonObject();
        resultsDesc.addProperty("type", "array");
        resultsDesc.addProperty("description",
                "Array of triage results. Each item: {id, real, severity, confidence, reasoning}");
        props.add("results", resultsDesc);
        return buildSchema(props, List.of("results"));
    }

    private JsonObject emptySchema() {
        JsonObject s = new JsonObject();
        s.addProperty("type", "object");
        s.add("properties", new JsonObject());
        return s;
    }

    private JsonObject buildSchema(JsonObject properties, List<String> required) {
        JsonObject s = new JsonObject();
        s.addProperty("type", "object");
        s.add("properties", properties);
        if (!required.isEmpty()) {
            JsonArray req = new JsonArray();
            required.forEach(req::add);
            s.add("required", req);
        }
        return s;
    }

    private void addStringProp(JsonObject props, String name, String description) {
        JsonObject p = new JsonObject();
        p.addProperty("type", "string");
        p.addProperty("description", description);
        props.add(name, p);
    }

    private void addBoolProp(JsonObject props, String name, String description) {
        JsonObject p = new JsonObject();
        p.addProperty("type", "boolean");
        p.addProperty("description", description);
        props.add(name, p);
    }

    private void addIntProp(JsonObject props, String name, String description) {
        JsonObject p = new JsonObject();
        p.addProperty("type", "integer");
        p.addProperty("description", description);
        props.add(name, p);
    }

    // =========================================================================
    // Misc helpers
    // =========================================================================

    private void log(String msg) {
        if (logger != null) logger.accept(msg);
        synchronized (logBuffer) {
            logBuffer.addLast("[McpBridge] " + msg);
            while (logBuffer.size() > LOG_MAX) logBuffer.removeFirst();
        }
    }

    private static String nvl(String s)  { return s != null ? s : ""; }

    private static String csvEsc(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n"))
            return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }
}
