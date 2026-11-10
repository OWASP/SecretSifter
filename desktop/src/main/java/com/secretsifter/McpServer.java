package com.secretsifter;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;

/**
 * Embedded MCP + REST server using HTTP transport (spec 2025-06-18).
 *   POST /mcp   — JSON-RPC 2.0 direct-response (no SSE)
 *   GET  /mcp   — health probe
 *   /api/*      — REST API for Python / curl automation
 */
public class McpServer {

    private int port;
    private String token;
    private final BulkScanPanel bulkPanel;
    private final ScanSettings  settings;
    private final LogManager    logger;
    private final AppPrefs      prefs;

    private HttpServer httpServer;
    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "mcp-worker");
        t.setDaemon(true);
        return t;
    });

    public McpServer(int port, String token, BulkScanPanel bulkPanel, ScanSettings settings,
                     LogManager logger, AppPrefs prefs) {
        this.port      = port;
        this.token     = token;
        this.bulkPanel = bulkPanel;
        this.settings  = settings;
        this.logger    = logger;
        this.prefs     = prefs;
    }

    public void setPort(int port)    { this.port  = port;  }
    public void setToken(String tok) { this.token = tok;   }
    public int  getPort()            { return port;        }
    public String getToken()         { return token;       }
    public boolean isRunning()       { return httpServer != null; }

    public void start() throws IOException {
        httpServer = HttpServer.create(new InetSocketAddress("localhost", port), 10);
        httpServer.createContext("/mcp", this::handleMcp);
        httpServer.createContext("/api", this::handleApi);
        httpServer.setExecutor(executor);
        httpServer.start();
    }

    public void stop() {
        if (httpServer != null) {
            httpServer.stop(0);
            httpServer = null;
        }
    }

    public void restart() throws IOException {
        stop();
        start();
    }

    // =========================================================================
    // HTTP handlers
    // =========================================================================

    private void handleMcp(HttpExchange ex) throws IOException {
        setCors(ex);
        String method = ex.getRequestMethod();
        if ("OPTIONS".equals(method)) { sendResponse(ex, 204, null); return; }
        if (!auth(ex)) { sendResponse(ex, 401, "{\"error\":\"invalid or missing Bearer token\"}"); return; }

        if ("GET".equals(method)) {
            sendResponse(ex, 200, "{\"server\":\"SecretSifter\",\"status\":\"ok\"}");
            return;
        }
        if (!"POST".equals(method)) { sendResponse(ex, 405, null); return; }

        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        JSONObject req;
        try { req = new JSONObject(body); } catch (Exception e) {
            sendResponse(ex, 400, err(null, "Invalid JSON").toString());
            return;
        }
        sendResponse(ex, 200, dispatch(req).toString());
    }

    private void handleApi(HttpExchange ex) throws IOException {
        setCors(ex);
        if ("OPTIONS".equals(ex.getRequestMethod())) { sendResponse(ex, 204, null); return; }
        if (!auth(ex)) { sendResponse(ex, 401, "{\"error\":\"invalid or missing Bearer token\"}"); return; }

        String path   = ex.getRequestURI().getPath();
        String method = ex.getRequestMethod();
        String query  = ex.getRequestURI().getQuery();
        String body   = "";
        if (!"GET".equals(method) && !"DELETE".equals(method)) {
            body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        }
        try {
            String result = routeApi(method, path, query, body);
            sendResponse(ex, 200, result);
        } catch (ApiException e) {
            sendResponse(ex, e.statusCode, "{\"error\":" + JSONObject.quote(e.getMessage()) + "}");
        } catch (Exception e) {
            sendResponse(ex, 500, "{\"error\":" + JSONObject.quote(e.getMessage() != null ? e.getMessage() : "internal error") + "}");
        }
    }

    private static class ApiException extends RuntimeException {
        final int statusCode;
        ApiException(int code, String msg) { super(msg); this.statusCode = code; }
    }

    private String routeApi(String method, String path, String query, String body) {
        if (path.equals("/api/scan")) {
            if ("POST".equals(method))   return apiStartScan(body);
            if ("GET".equals(method))    return doGetScanStatus().getJSONArray("content").getJSONObject(0).getString("text");
            if ("DELETE".equals(method)) return doStopScan().getJSONArray("content").getJSONObject(0).getString("text");
            throw new ApiException(405, "Method not allowed");
        }
        if (path.equals("/api/scan/status") && "GET".equals(method)) {
            return doGetScanStatus().getJSONArray("content").getJSONObject(0).getString("text");
        }
        if (path.startsWith("/api/findings/")) {
            String rowStr = path.substring("/api/findings/".length());
            int row;
            try { row = Integer.parseInt(rowStr); } catch (Exception e) { throw new ApiException(400, "Invalid row number"); }
            if ("DELETE".equals(method)) {
                JSONObject args = new JSONObject().put("index", row - 1);
                return doDeleteFinding(args).getJSONArray("content").getJSONObject(0).getString("text");
            }
            if ("PATCH".equals(method)) {
                JSONObject args = body.isBlank() ? new JSONObject() : new JSONObject(body);
                args.put("index", row - 1);
                return doUpdateFinding(args).getJSONArray("content").getJSONObject(0).getString("text");
            }
            throw new ApiException(405, "Method not allowed");
        }
        if (path.equals("/api/findings")) {
            if ("GET".equals(method)) {
                JSONObject args = new JSONObject();
                if (query != null) {
                    String sev = queryParam(query, "severity"); String tgt = queryParam(query, "target");
                    if (sev != null) args.put("severity", sev);
                    if (tgt != null) args.put("target_url", tgt);
                }
                return doGetFindings(args).getJSONArray("content").getJSONObject(0).getString("text");
            }
            if ("DELETE".equals(method)) return doClearFindings().getJSONArray("content").getJSONObject(0).getString("text");
            throw new ApiException(405, "Method not allowed");
        }
        if (path.equals("/api/report") && "POST".equals(method)) {
            JSONObject args = body.isBlank() ? new JSONObject() : new JSONObject(body);
            return doExportReport(args).getJSONArray("content").getJSONObject(0).getString("text");
        }
        if (path.equals("/api/settings")) {
            if ("GET".equals(method))   return doGetSettings().getJSONArray("content").getJSONObject(0).getString("text");
            if ("PATCH".equals(method)) {
                JSONObject args = body.isBlank() ? new JSONObject() : new JSONObject(body);
                return doSetSettings(args).getJSONArray("content").getJSONObject(0).getString("text");
            }
            throw new ApiException(405, "Method not allowed");
        }
        if (path.equals("/api/targets") && "GET".equals(method)) {
            return doGetTargetStatus(new JSONObject()).getJSONArray("content").getJSONObject(0).getString("text");
        }
        if (path.equals("/api/rules")) {
            if ("GET".equals(method))  return doGetCustomRules().getJSONArray("content").getJSONObject(0).getString("text");
            if ("PUT".equals(method)) {
                JSONObject args = body.isBlank() ? new JSONObject() : new JSONObject(body);
                if (!args.has("rules") && body.trim().startsWith("[")) {
                    JSONArray arr = new JSONArray(body);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < arr.length(); i++) { if (sb.length()>0) sb.append("\n"); sb.append(arr.getString(i)); }
                    args.put("rules", sb.toString());
                }
                return doSetCustomRules(args).getJSONArray("content").getJSONObject(0).getString("text");
            }
            if ("POST".equals(method)) {
                JSONObject args = body.isBlank() ? new JSONObject() : new JSONObject(body);
                return doAddCustomRule(args).getJSONArray("content").getJSONObject(0).getString("text");
            }
            throw new ApiException(405, "Method not allowed");
        }
        if (path.equals("/api/logs")) {
            if ("GET".equals(method))    return doGetLogs(new JSONObject()).getJSONArray("content").getJSONObject(0).getString("text");
            if ("DELETE".equals(method)) return doClearLogs().getJSONArray("content").getJSONObject(0).getString("text");
            throw new ApiException(405, "Method not allowed");
        }
        throw new ApiException(404, "Not found: " + path);
    }

    private String apiStartScan(String body) {
        JSONObject req = body.isBlank() ? new JSONObject() : new JSONObject(body);
        if (req.has("urls") && req.opt("urls") instanceof JSONArray arr) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < arr.length(); i++) { if (sb.length() > 0) sb.append("\n"); sb.append(arr.getString(i)); }
            req.put("urls", sb.toString());
        }
        return doStartScan(req).getJSONArray("content").getJSONObject(0).getString("text");
    }

    // =========================================================================
    // JSON-RPC dispatch
    // =========================================================================

    private JSONObject dispatch(JSONObject req) {
        String method = req.optString("method");
        Object id     = req.opt("id");
        try {
            JSONObject result;
            if ("initialize".equals(method))             result = handleInit();
            else if ("tools/list".equals(method))        result = handleList();
            else if ("tools/call".equals(method))        result = handleCall(req.optJSONObject("params"));
            else if (method.startsWith("notifications/"))result = new JSONObject();
            else if ("ping".equals(method))              result = new JSONObject();
            else throw new RuntimeException("Unknown method: " + method);
            return ok(id, result);
        } catch (Exception e) {
            return err(id, e.getMessage());
        }
    }

    private JSONObject handleInit() {
        return new JSONObject()
            .put("protocolVersion", "2025-06-18")
            .put("serverInfo", new JSONObject().put("name", "secretsifter-desktop").put("version", "1.8.0"))
            .put("capabilities", new JSONObject().put("tools", new JSONObject()));
    }

    private JSONObject handleList() {
        JSONArray tools = new JSONArray();

        // ── Query ──────────────────────────────────────────────────────────────
        tools.put(tool("secretsifter_get_findings",
            "Get secrets found by SecretSifter. Returns detected API keys, credentials, " +
            "and other sensitive data. Optionally filter by severity or target URL. " +
            "Each finding has an 'index' field you can use with secretsifter_update_finding_severity or secretsifter_delete_finding.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("severity",   prop("string", "Minimum severity: HIGH, MEDIUM, LOW, INFORMATION"))
                    .put("target_url", prop("string", "Filter to findings from this seed URL (substring match)")))
                .put("required", new JSONArray())));

        tools.put(tool("secretsifter_get_summary",
            "Get a count of SecretSifter findings grouped by severity.",
            emptySchema()));

        tools.put(tool("secretsifter_get_scan_status",
            "Get the current scan status: whether a scan is running or paused, " +
            "how many URLs have been processed, and how many findings exist so far.",
            emptySchema()));

        // ── Control ───────────────────────────────────────────────────────────
        tools.put(tool("secretsifter_start_bulk_scan",
            "Start a secret scan. Provide either 'urls' (a list or newline-separated string) " +
            "or 'targets_file' (path to a text file with one URL per line). " +
            "Use 'batch_start' and 'batch_size' to scan a slice of a large target file. " +
            "Scan runs asynchronously; poll secretsifter_get_scan_status to monitor progress.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("urls",          prop("string", "Newline or comma-separated list of URLs to scan"))
                    .put("targets_file",  prop("string", "Path to a text file with one URL per line"))
                    .put("batch_start",   prop("integer", "Line index (0-based) to start reading from the file"))
                    .put("batch_size",    prop("integer", "Number of URLs to read from the file (default: all)"))
                    .put("threads",       prop("integer", "Concurrent fetch threads 1-50 (default 10)"))
                    .put("browser_mode",         prop("boolean", "Use headless browser (Playwright) for JS-heavy sites"))
                    .put("follow_scripts",       prop("boolean", "Follow <script src> links (default true)"))
                    .put("follow_chunks",        prop("boolean", "Follow webpack chunk references (default true)"))
                    .put("cross_origin_apis",    prop("boolean", "Scan API responses from cross-origin domains called by the target page (default false)"))
                    .put("strict_scope",         prop("boolean", "Restrict JS capture to the exact seed host only (default false)")))
                .put("required", new JSONArray())));

        tools.put(tool("secretsifter_cancel_scan",
            "Stop the currently running scan immediately.",
            emptySchema()));

        tools.put(tool("secretsifter_pause_scan",
            "Pause the currently running scan (browser mode only). Use secretsifter_resume_scan to continue.",
            emptySchema()));

        tools.put(tool("secretsifter_resume_scan",
            "Resume a paused scan.",
            emptySchema()));

        tools.put(tool("secretsifter_clear_results",
            "Remove all findings from the current session. Cannot be undone.",
            emptySchema()));

        // ── Triage ────────────────────────────────────────────────────────────
        tools.put(tool("secretsifter_update_finding_severity",
            "Update the severity and/or confidence of a finding. " +
            "Use the 'index' value returned by secretsifter_get_findings.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("index",      prop("integer", "Finding index from secretsifter_get_findings"))
                    .put("severity",   prop("string",  "New severity: HIGH, MEDIUM, LOW, INFORMATION"))
                    .put("confidence", prop("string",  "New confidence: CERTAIN, FIRM, TENTATIVE")))
                .put("required", new JSONArray(List.of("index")))));

        tools.put(tool("secretsifter_delete_finding",
            "Delete (dismiss) one or more findings as false positives. " +
            "Pass a single 'index' or an array of 'indices'.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("index",   prop("integer", "Single finding index to delete"))
                    .put("indices", new JSONObject().put("type", "array")
                        .put("items", new JSONObject().put("type", "integer"))
                        .put("description", "Array of finding indices to delete")))
                .put("required", new JSONArray())));

        // ── Export ────────────────────────────────────────────────────────────
        tools.put(tool("secretsifter_export_report",
            "Export all findings to a file. Supported formats: csv, json, html. " +
            "Optionally specify output_path; defaults to Desktop/secretsifter-report.<ext>. " +
            "Returns the path of the written file.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("format",      prop("string", "csv, json, or html"))
                    .put("output_path", prop("string", "Full file path for the report (optional)")))
                .put("required", new JSONArray(List.of("format")))));

        // ── Custom Rules ──────────────────────────────────────────────────────
        tools.put(tool("secretsifter_get_custom_rules",
            "Get the current custom regex rules. Each rule has the format: RuleName | regex | severity",
            emptySchema()));

        tools.put(tool("secretsifter_set_custom_rules",
            "Set custom regex rules for the scanner. Replaces all existing custom rules. " +
            "Each line: RuleName | regex | severity  (severity: HIGH/MEDIUM/LOW/INFORMATION). " +
            "Lines starting with # are comments. Pass empty string to clear all rules.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("rules",   prop("string",  "Newline-separated rules in format: RuleName | regex | severity"))
                    .put("enabled", prop("boolean", "Enable or disable custom rules (default true)")))
                .put("required", new JSONArray(List.of("rules")))));

        tools.put(tool("secretsifter_add_custom_rule",
            "Add a single custom regex rule. The regex is validated before saving. " +
            "Use secretsifter_get_custom_rules to list existing rules.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("name",     prop("string", "Rule name (e.g. MyToken)"))
                    .put("regex",    prop("string", "Java regex pattern"))
                    .put("severity", prop("string", "HIGH, MEDIUM, LOW, or INFORMATION")))
                .put("required", new JSONArray(List.of("name", "regex", "severity")))));

        // ── Settings ──────────────────────────────────────────────────────────
        tools.put(tool("secretsifter_get_settings",
            "Get the current scan settings (tier, entropy threshold, PII detection, etc.).",
            emptySchema()));

        tools.put(tool("secretsifter_update_settings",
            "Update scan settings. Only fields provided are changed.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("tier",              prop("string",  "Scan depth: FULL, LIGHT, or FAST"))
                    .put("entropy_threshold", prop("number",  "Shannon entropy minimum 0.0-6.0 (default 3.5)"))
                    .put("pii_enabled",       prop("boolean", "Enable SSN and credit card detection"))
                    .put("scan_requests",     prop("boolean", "Scan request headers for hardcoded tokens")))
                .put("required", new JSONArray())));

        // ── Target scan status ────────────────────────────────────────────────
        tools.put(tool("secretsifter_get_target_status",
            "Get the per-target scan outcome for every URL in the current session. " +
            "Shows which targets are reachable, unreachable, behind authentication, or timed out. " +
            "Optionally filter by outcome: ok, failed, auth, timeout.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("filter", prop("string", "Filter results: ok, failed, auth, timeout, or omit for all")))
                .put("required", new JSONArray())));

        // ── Targets file preview ──────────────────────────────────────────────
        tools.put(tool("secretsifter_preview_targets_file",
            "Preview URLs from a targets file without starting a scan. " +
            "Returns the total line count and a slice of URLs for inspection.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("file_path",   prop("string",  "Path to targets file"))
                    .put("batch_start", prop("integer", "Starting line index (default 0)"))
                    .put("batch_size",  prop("integer", "Lines to return (default 20)")))
                .put("required", new JSONArray(List.of("file_path")))));

        // ── Logs ──────────────────────────────────────────────────────────────
        tools.put(tool("secretsifter_get_logs",
            "Read the SecretSifter application log. Returns the most recent lines. " +
            "Filter by level (ERROR or INFO) and limit the number of lines returned.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("filter", prop("string", "Log level filter: ERROR or INFO (omit for all)"))
                    .put("limit",  prop("integer", "Max lines to return, newest first (default 200)")))
                .put("required", new JSONArray())));

        tools.put(tool("secretsifter_clear_logs",
            "Clear the SecretSifter application log buffer.",
            emptySchema()));

        // ── CDN blocklist ─────────────────────────────────────────────────────
        tools.put(tool("secretsifter_get_cdn_blocklist",
            "Get the current CDN / third-party domain blocklist. " +
            "Hosts on this list are skipped by the scanner.",
            emptySchema()));

        tools.put(tool("secretsifter_set_cdn_blocklist",
            "Replace the CDN / third-party domain blocklist. " +
            "Pass a newline-separated list of hostname substrings (e.g. 'segment.com'). " +
            "Lines starting with # are ignored.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("entries", prop("string", "Newline-separated hostname entries")))
                .put("required", new JSONArray(List.of("entries")))));

        // ── Key name filters ──────────────────────────────────────────────────
        tools.put(tool("secretsifter_get_key_filters",
            "Get the key name blocklist and allowlist. " +
            "Findings whose key name contains a blocklist entry are suppressed; " +
            "allowlist entries bypass noise filters and are always reported.",
            emptySchema()));

        tools.put(tool("secretsifter_set_key_filters",
            "Update the key name blocklist and/or allowlist. " +
            "Pass a JSON array or newline-separated string for each list. " +
            "Only fields provided are changed.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("key_blocklist", prop("string", "Newline-separated key name substrings to suppress"))
                    .put("key_allowlist", prop("string", "Newline-separated key name substrings that bypass noise filters")))
                .put("required", new JSONArray())));

        // ── Built-in pattern catalogue ────────────────────────────────────────
        tools.put(tool("secretsifter_list_builtin_patterns",
            "List all built-in detection rules: rule ID, rule name, and severity. " +
            "Includes all anchored vendor token rules plus the names of generic rules.",
            emptySchema()));

        // ── Bulk findings operations ──────────────────────────────────────────
        tools.put(tool("secretsifter_bulk_delete_findings",
            "Delete all findings that match a severity and/or confidence filter in one call. " +
            "Useful for dismissing entire classes of false positives at once.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("severity",   prop("string", "Delete findings at this exact severity: HIGH, MEDIUM, LOW, INFORMATION"))
                    .put("confidence", prop("string", "Delete findings at this exact confidence: CERTAIN, FIRM, TENTATIVE"))
                    .put("rule_id",    prop("string", "Delete findings from this rule ID (exact or prefix match)")))
                .put("required", new JSONArray())));

        // ── HAR file scan ─────────────────────────────────────────────────────
        tools.put(tool("secretsifter_scan_har_file",
            "Scan a HAR (HTTP Archive) file for secrets. " +
            "The scan runs asynchronously — use secretsifter_get_findings and secretsifter_get_logs to monitor results.",
            new JSONObject().put("type", "object")
                .put("properties", new JSONObject()
                    .put("file_path", prop("string", "Full path to the .har file")))
                .put("required", new JSONArray(List.of("file_path")))));

        return new JSONObject().put("tools", tools);
    }

    private JSONObject handleCall(JSONObject params) {
        if (params == null) throw new RuntimeException("Missing params");
        String name = params.optString("name");
        JSONObject args = params.optJSONObject("arguments");
        if (args == null) args = new JSONObject();
        if ("secretsifter_get_findings".equals(name))              return doGetFindings(args);
        if ("secretsifter_get_summary".equals(name))               return doGetSummary();
        if ("secretsifter_get_scan_status".equals(name))           return doGetScanStatus();
        if ("secretsifter_start_bulk_scan".equals(name))           return doStartScan(args);
        if ("secretsifter_cancel_scan".equals(name))               return doStopScan();
        if ("secretsifter_pause_scan".equals(name))                return doPauseScan();
        if ("secretsifter_resume_scan".equals(name))               return doResumeScan();
        if ("secretsifter_clear_results".equals(name))             return doClearFindings();
        if ("secretsifter_update_finding_severity".equals(name))   return doUpdateFinding(args);
        if ("secretsifter_delete_finding".equals(name))            return doDeleteFinding(args);
        if ("secretsifter_export_report".equals(name))             return doExportReport(args);
        if ("secretsifter_get_custom_rules".equals(name))          return doGetCustomRules();
        if ("secretsifter_set_custom_rules".equals(name))          return doSetCustomRules(args);
        if ("secretsifter_add_custom_rule".equals(name))           return doAddCustomRule(args);
        if ("secretsifter_get_settings".equals(name))              return doGetSettings();
        if ("secretsifter_update_settings".equals(name))           return doSetSettings(args);
        if ("secretsifter_get_target_status".equals(name))         return doGetTargetStatus(args);
        if ("secretsifter_preview_targets_file".equals(name))      return doPreviewTargetsFile(args);
        if ("secretsifter_get_logs".equals(name))                  return doGetLogs(args);
        if ("secretsifter_clear_logs".equals(name))                return doClearLogs();
        if ("secretsifter_get_cdn_blocklist".equals(name))         return doGetCdnBlocklist();
        if ("secretsifter_set_cdn_blocklist".equals(name))         return doSetCdnBlocklist(args);
        if ("secretsifter_get_key_filters".equals(name))           return doGetKeyFilters();
        if ("secretsifter_set_key_filters".equals(name))           return doSetKeyFilters(args);
        if ("secretsifter_list_builtin_patterns".equals(name))     return doListBuiltinPatterns();
        if ("secretsifter_bulk_delete_findings".equals(name))      return doBulkDeleteFindings(args);
        if ("secretsifter_scan_har_file".equals(name))             return doScanHarFile(args);
        throw new RuntimeException("Unknown tool: " + name);
    }

    // =========================================================================
    // Tool implementations
    // =========================================================================

    private JSONObject doGetFindings(JSONObject args) {
        String minSev       = args.optString("severity",   null);
        String targetFilter = args.optString("target_url", null);
        List<SecretFinding> all = bulkPanel.getFindings();
        JSONArray arr = new JSONArray();
        for (int i = 0; i < all.size(); i++) {
            SecretFinding f = all.get(i);
            if (minSev != null && !meetsMinSeverity(f.severity(), minSev)) continue;
            if (targetFilter != null && !containsIgnoreCase(f.targetUrl() + f.sourceUrl(), targetFilter)) continue;
            arr.put(new JSONObject()
                .put("index",      i)
                .put("issueId",    f.issueId())
                .put("fingerprint", f.fingerprint())
                .put("ruleId",     f.ruleId())
                .put("ruleName",   f.ruleName())
                .put("keyName",    f.keyName())
                .put("value",      f.matchedValue())
                .put("severity",   f.severity())
                .put("confidence", f.confidence())
                .put("validation", f.validationLabel())
                .put("sourceUrl",  f.sourceUrl())
                .put("targetUrl",  f.targetUrl() != null ? f.targetUrl() : "")
                .put("line",       f.lineNumber())
                .put("context",    f.context() != null ? f.context() : ""));
        }
        if (arr.isEmpty()) {
            return textContent("No findings" +
                    (minSev != null ? " at " + minSev + " or above" : "") +
                    (targetFilter != null ? " for " + targetFilter : "") + ".");
        }
        return textContent(arr.toString(2));
    }

    private JSONObject doGetSummary() {
        List<SecretFinding> all = bulkPanel.getFindings();
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String s : List.of("HIGH", "MEDIUM", "LOW", "INFORMATION")) counts.put(s, 0);
        for (SecretFinding f : all) counts.merge(f.severity(), 1, Integer::sum);
        return textContent(new JSONObject()
            .put("total", all.size())
            .put("bySeverity", new JSONObject(counts))
            .toString(2));
    }

    private JSONObject doGetScanStatus() {
        return textContent(bulkPanel.getScanStatus().toString(2));
    }

    private JSONObject doStartScan(JSONObject args) {
        List<String> urls = new ArrayList<>();

        String targetsFile = args.optString("targets_file", null);
        if (targetsFile != null && !targetsFile.isBlank()) {
            try {
                List<String> lines = Files.readAllLines(new java.io.File(targetsFile).toPath(), StandardCharsets.UTF_8);
                int start = Math.max(0, args.optInt("batch_start", 0));
                int size  = args.optInt("batch_size", -1);
                List<String> slice = lines.subList(start, size < 0 ? lines.size() : Math.min(start + size, lines.size()));
                for (String l : slice) { String t = l.trim(); if (!t.isEmpty() && !t.startsWith("#")) urls.add(t); }
            } catch (Exception e) {
                return textContent("Error reading file: " + e.getMessage());
            }
        }

        String urlsArg = args.optString("urls", null);
        if (urlsArg != null && !urlsArg.isBlank()) {
            for (String u : urlsArg.split("[,\n]")) { String t = u.trim(); if (!t.isEmpty()) urls.add(t); }
        }

        if (urls.isEmpty()) return textContent("No URLs provided. Use 'urls' or 'targets_file' parameter.");

        int     threads         = Math.max(1, Math.min(50, args.optInt("threads", 10)));
        boolean browserMode     = args.optBoolean("browser_mode",      false);
        boolean followScripts   = args.optBoolean("follow_scripts",    true);
        boolean followChunks    = args.optBoolean("follow_chunks",     true);
        boolean crossOriginApis = args.optBoolean("cross_origin_apis", settings.isFollowCrossOriginApis());
        boolean strictScope     = args.optBoolean("strict_scope",      settings.isStrictScope());

        bulkPanel.startScanProgrammatic(urls, threads, browserMode, followScripts, followChunks, crossOriginApis, strictScope);
        return textContent("Scan started for " + urls.size() + " URL(s) with " + threads +
                " thread(s). Use secretsifter_get_scan_status to monitor progress.");
    }

    private JSONObject doStopScan()   { bulkPanel.stopScan();   return textContent("Scan cancelled."); }
    private JSONObject doPauseScan()  { bulkPanel.pauseScan();  return textContent("Pause requested."); }
    private JSONObject doResumeScan() { bulkPanel.resumeScan(); return textContent("Resume requested."); }

    private JSONObject doClearFindings() {
        List<SecretFinding> all = bulkPanel.getFindings();
        for (int i = all.size() - 1; i >= 0; i--) bulkPanel.deleteFinding(i);
        return textContent("Results cleared.");
    }

    private JSONObject doUpdateFinding(JSONObject args) {
        int index = args.optInt("index", -1);
        if (index < 0) return textContent("'index' is required.");
        String sev  = args.optString("severity",   null);
        String conf = args.optString("confidence", null);
        if (sev == null && conf == null) return textContent("Provide at least 'severity' or 'confidence'.");
        boolean ok = bulkPanel.updateFinding(index, sev, conf);
        return textContent(ok ? "Finding " + index + " updated." : "Index " + index + " out of range.");
    }

    private JSONObject doDeleteFinding(JSONObject args) {
        JSONArray indices = args.optJSONArray("indices");
        List<Integer> toDelete = new ArrayList<>();
        if (indices != null) {
            for (int i = 0; i < indices.length(); i++) toDelete.add(indices.getInt(i));
        } else {
            int idx = args.optInt("index", -1);
            if (idx < 0) return textContent("Provide 'index' or 'indices'.");
            toDelete.add(idx);
        }
        toDelete.sort(Comparator.reverseOrder());
        int deleted = 0;
        for (int idx : toDelete) { if (bulkPanel.deleteFinding(idx)) deleted++; }
        return textContent("Deleted " + deleted + " finding(s).");
    }

    private JSONObject doExportReport(JSONObject args) {
        String format = args.optString("format", "json").toLowerCase();
        if (!Set.of("csv", "json", "html").contains(format))
            return textContent("Unsupported format. Use csv, json, or html.");
        String outputPath = args.optString("output_path", null);
        java.io.File outFile;
        if (outputPath != null && !outputPath.isBlank()) {
            outFile = new java.io.File(outputPath);
        } else {
            String desktop = System.getProperty("user.home") + "/Desktop";
            outFile = new java.io.File(desktop, "secretsifter-report." + format);
        }
        java.io.File written = bulkPanel.exportReport(format, outFile);
        if (written == null) return textContent("Export failed or no findings to export.");
        return textContent("Report saved to: " + written.getAbsolutePath());
    }

    private JSONObject doGetCustomRules() {
        List<String> rules = settings.getCustomRules();
        if (rules.isEmpty()) return textContent("No custom rules configured.\n" +
                "Format: RuleName | regex | severity  (severity: HIGH/MEDIUM/LOW/INFORMATION)");
        JSONObject result = new JSONObject()
                .put("enabled", settings.isCustomRulesEnabled())
                .put("count", rules.size())
                .put("rules", String.join("\n", rules));
        return textContent(result.toString(2));
    }

    private JSONObject doSetCustomRules(JSONObject args) {
        String rulesText = args.optString("rules", "");
        List<String> parsed = new ArrayList<>();
        for (String line : rulesText.split("\n")) { String t = line.trim(); if (!t.isEmpty()) parsed.add(t); }
        settings.setCustomRules(parsed);
        if (args.has("enabled")) settings.setCustomRulesEnabled(args.optBoolean("enabled", true));
        settings.saveToPrefs(prefs);
        prefs.flush();
        return textContent("Custom rules updated: " + parsed.size() + " rule(s) loaded.");
    }

    private JSONObject doAddCustomRule(JSONObject args) {
        String name     = args.optString("name",     null);
        String regex    = args.optString("regex",    null);
        String severity = args.optString("severity", null);
        if (name == null || name.isBlank())     return textContent("'name' is required.");
        if (regex == null || regex.isBlank())   return textContent("'regex' is required.");
        if (severity == null || severity.isBlank()) return textContent("'severity' is required.");
        try { java.util.regex.Pattern.compile(regex); } catch (Exception e) {
            return textContent("Invalid regex: " + e.getMessage());
        }
        String newRule = name.trim() + " | " + regex.trim() + " | " + severity.trim().toUpperCase();
        List<String> rules = new ArrayList<>(settings.getCustomRules());
        rules.add(newRule);
        settings.setCustomRules(rules);
        settings.saveToPrefs(prefs);
        prefs.flush();
        return textContent("Custom rule added: " + newRule);
    }

    private JSONObject doGetSettings() {
        JSONObject s = new JSONObject()
                .put("tier",                     settings.getTier().name())
                .put("entropy_threshold",        settings.getEntropyThreshold())
                .put("pii_enabled",              settings.isPiiEnabled())
                .put("scan_requests",            settings.isScanRequestsEnabled())
                .put("browser_enabled",          settings.isPlaywrightEnabled())
                .put("browser_max_pages",        settings.getPlaywrightMaxPages())
                .put("browser_path",             settings.getBrowserPath())
                .put("url_timeout_seconds",      settings.getUrlTimeoutSeconds())
                .put("custom_rules_enabled",     settings.isCustomRulesEnabled())
                .put("follow_cross_origin_apis", settings.isFollowCrossOriginApis())
                .put("strict_scope",             settings.isStrictScope())
                .put("custom_rules_count",       settings.getCustomRules().size())
                .put("key_blocklist_count",      settings.getKeyBlocklist().size())
                .put("key_allowlist_count",      settings.getKeyAllowlist().size())
                .put("cdn_blocklist_count",      settings.getCdnBlocklist().size());
        return textContent(s.toString(2));
    }

    private JSONObject doSetSettings(JSONObject args) {
        if (args.has("tier")) {
            try { settings.setTier(ScanSettings.ScanTier.valueOf(args.getString("tier").toUpperCase())); }
            catch (IllegalArgumentException e) { return textContent("Invalid tier. Use FULL, LIGHT, or FAST."); }
        }
        if (args.has("entropy_threshold"))    settings.setEntropyThreshold(args.getDouble("entropy_threshold"));
        if (args.has("pii_enabled"))          settings.setPiiEnabled(args.getBoolean("pii_enabled"));
        if (args.has("scan_requests"))        settings.setScanRequestsEnabled(args.getBoolean("scan_requests"));
        if (args.has("browser_enabled"))      settings.setPlaywrightEnabled(args.getBoolean("browser_enabled"));
        if (args.has("browser_max_pages"))    settings.setPlaywrightMaxPages(args.getInt("browser_max_pages"));
        if (args.has("browser_path"))         settings.setBrowserPath(args.getString("browser_path"));
        if (args.has("url_timeout_seconds"))  settings.setUrlTimeoutSeconds(args.getInt("url_timeout_seconds"));
        if (args.has("custom_rules_enabled")) settings.setCustomRulesEnabled(args.getBoolean("custom_rules_enabled"));
        if (args.has("follow_cross_origin_apis")) settings.setFollowCrossOriginApis(args.getBoolean("follow_cross_origin_apis"));
        if (args.has("strict_scope"))             settings.setStrictScope(args.getBoolean("strict_scope"));
        settings.saveToPrefs(prefs);
        prefs.flush();
        return textContent("Settings updated:\n" + doGetSettings().getJSONArray("content").getJSONObject(0).getString("text"));
    }

    private JSONObject doGetTargetStatus(JSONObject args) {
        String filter = args.optString("filter", null);
        if (filter != null) filter = filter.toLowerCase().trim();
        List<org.json.JSONObject> rows = bulkPanel.getTargetStatuses();
        if (rows.isEmpty()) return textContent("No target status recorded yet. Start a scan first.");
        JSONArray arr = new JSONArray();
        int ok = 0, failed = 0, auth = 0, timeout = 0;
        for (org.json.JSONObject row : rows) {
            String icon   = row.optString("icon", "");
            String detail = row.optString("detail", "").toLowerCase();
            boolean isOk      = icon.contains("\u2705") || detail.startsWith("ok");
            boolean isFailed  = icon.contains("\u274c") || detail.contains("unreachable") || detail.contains("http ");
            boolean isAuth    = icon.contains("\uD83D\uDD12") || detail.contains("auth");
            boolean isTimeout = icon.contains("\u23f1")  || detail.contains("timed out");
            if (isOk) ok++; else if (isAuth) auth++; else if (isTimeout) timeout++; else if (isFailed) failed++;
            boolean include = filter == null
                    || ("ok".equals(filter)      && isOk)
                    || ("failed".equals(filter)  && isFailed)
                    || ("auth".equals(filter)    && isAuth)
                    || ("timeout".equals(filter) && isTimeout);
            if (include) arr.put(row);
        }
        JSONObject summary = new JSONObject().put("total", rows.size()).put("ok", ok)
                .put("failed", failed).put("auth", auth).put("timeout", timeout);
        if (arr.isEmpty()) return textContent("No targets matched filter '" + filter + "'.\n" + summary.toString(2));
        return textContent(new JSONObject().put("summary", summary).put("targets", arr).toString(2));
    }

    private JSONObject doPreviewTargetsFile(JSONObject args) {
        String filePath = args.optString("file_path", null);
        if (filePath == null || filePath.isBlank()) return textContent("'file_path' is required.");
        try {
            List<String> lines = Files.readAllLines(new java.io.File(filePath).toPath(), StandardCharsets.UTF_8);
            int start = Math.max(0, args.optInt("batch_start", 0));
            int size  = args.optInt("batch_size", 20);
            List<String> slice = lines.subList(start, Math.min(start + size, lines.size()));
            return textContent(new JSONObject()
                    .put("total_lines", lines.size())
                    .put("batch_start", start)
                    .put("batch_size",  slice.size())
                    .put("urls", new JSONArray(slice)).toString(2));
        } catch (Exception e) { return textContent("Error reading file: " + e.getMessage()); }
    }

    private JSONObject doGetLogs(JSONObject args) {
        String filter = args.optString("filter", null);
        int limit = Math.max(1, args.optInt("limit", 200));
        String allLogs = logger.getAllLogs();
        if (allLogs.isBlank()) return textContent("Log buffer is empty.");
        String[] lines = allLogs.split("\n");
        List<String> result = new ArrayList<>();
        String filterTag = filter != null ? "[" + filter.toUpperCase() + "]" : null;
        for (int i = lines.length - 1; i >= 0 && result.size() < limit; i--) {
            if (filterTag == null || lines[i].contains(filterTag)) result.add(0, lines[i]);
        }
        return textContent(result.isEmpty() ? "No log lines match filter '" + filter + "'." : String.join("\n", result));
    }

    private JSONObject doClearLogs() { logger.clear(); return textContent("Log buffer cleared."); }

    private JSONObject doGetCdnBlocklist() {
        List<String> list = settings.getCdnBlocklist();
        return textContent(new JSONObject().put("count", list.size()).put("entries", String.join("\n", list)).toString(2));
    }

    private JSONObject doSetCdnBlocklist(JSONObject args) {
        String entriesText = args.optString("entries", "");
        List<String> parsed = new ArrayList<>();
        for (String line : entriesText.split("\n")) { String t = line.trim(); if (!t.isEmpty() && !t.startsWith("#")) parsed.add(t); }
        settings.setCdnBlocklist(parsed);
        settings.saveToPrefs(prefs);
        prefs.flush();
        return textContent("CDN blocklist updated: " + parsed.size() + " entries.");
    }

    private JSONObject doGetKeyFilters() {
        return textContent(new JSONObject()
                .put("key_blocklist", new JSONArray(settings.getKeyBlocklist()))
                .put("key_allowlist", new JSONArray(settings.getKeyAllowlist())).toString(2));
    }

    private JSONObject doSetKeyFilters(JSONObject args) {
        StringBuilder sb = new StringBuilder();
        if (args.has("key_blocklist")) { List<String> bl = splitLines(args.optString("key_blocklist", "")); settings.setKeyBlocklist(bl); sb.append("Key blocklist: ").append(bl.size()).append(" entries. "); }
        if (args.has("key_allowlist")) { List<String> al = splitLines(args.optString("key_allowlist", "")); settings.setKeyAllowlist(al); sb.append("Key allowlist: ").append(al.size()).append(" entries."); }
        if (sb.length() > 0) { settings.saveToPrefs(prefs); prefs.flush(); }
        return textContent(sb.length() == 0 ? "No filter provided. Specify key_blocklist and/or key_allowlist." : sb.toString().trim());
    }

    private JSONObject doListBuiltinPatterns() {
        JSONArray anchored = new JSONArray();
        for (Patterns.AnchoredRule rule : Patterns.ANCHORED_RULES) {
            anchored.put(new JSONObject().put("ruleId", rule.ruleId()).put("ruleName", rule.ruleName()).put("severity", rule.severity()));
        }
        JSONArray generic = new JSONArray(List.of(
                "GENERIC_KV        — Secret in Key-Value Pair (all tiers)",
                "URL_CREDS         — URL with Embedded Credentials",
                "URL_QUERY_CREDS   — URL with Password in Query Parameters",
                "DB_CONN           — Database/Broker Connection String",
                "DB_CONN_DOTNET    — ADO.NET/SQL Server Connection String",
                "ENTROPY_TOKEN     — High-Entropy Secret Token (FULL tier)",
                "GETTER_FUNC       — Secret Returned from Getter Function",
                "JSON_WALK         — Secret Found in JSON Response Walk",
                "REQ_HEADER        — Secret in Request Header",
                "CUSTOM_*          — Custom regex rule (user-defined)"
        ));
        return textContent(new JSONObject()
                .put("anchored_rule_count", anchored.length())
                .put("anchored_rules",      anchored)
                .put("generic_rules",       generic).toString(2));
    }

    private JSONObject doBulkDeleteFindings(JSONObject args) {
        String sevFilter  = args.optString("severity",   null);
        String confFilter = args.optString("confidence", null);
        String ruleFilter = args.optString("rule_id",    null);
        if (sevFilter == null && confFilter == null && ruleFilter == null)
            return textContent("Provide at least one of: severity, confidence, rule_id.");
        if (sevFilter  != null) sevFilter  = sevFilter.toUpperCase();
        if (confFilter != null) confFilter = confFilter.toUpperCase();
        if (ruleFilter != null) ruleFilter = ruleFilter.toUpperCase();
        List<SecretFinding> all = bulkPanel.getFindings();
        List<Integer> toDelete = new ArrayList<>();
        for (int i = 0; i < all.size(); i++) {
            SecretFinding f = all.get(i);
            boolean match = true;
            if (sevFilter  != null && !sevFilter.equals(f.severity().toUpperCase()))    match = false;
            if (confFilter != null && !confFilter.equals(f.confidence().toUpperCase())) match = false;
            if (ruleFilter != null && !f.ruleId().toUpperCase().startsWith(ruleFilter)) match = false;
            if (match) toDelete.add(i);
        }
        toDelete.sort(Comparator.reverseOrder());
        for (int idx : toDelete) bulkPanel.deleteFinding(idx);
        return textContent("Deleted " + toDelete.size() + " finding(s) matching the filter.");
    }

    private JSONObject doScanHarFile(JSONObject args) {
        String filePath = args.optString("file_path", null);
        if (filePath == null || filePath.isBlank()) return textContent("'file_path' is required.");
        String result = bulkPanel.importHarFile(new java.io.File(filePath));
        return textContent(result);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static void sendResponse(HttpExchange ex, int code, String body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json");
        if (body == null || body.isEmpty()) {
            ex.sendResponseHeaders(code, -1);
        } else {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(code, bytes.length);
            ex.getResponseBody().write(bytes);
        }
        ex.close();
    }

    private static final List<String> SEV_ORDER = List.of("INFORMATION", "LOW", "MEDIUM", "HIGH");

    private static boolean meetsMinSeverity(String actual, String min) {
        int a = SEV_ORDER.indexOf(actual != null ? actual.toUpperCase() : "");
        int m = SEV_ORDER.indexOf(min.toUpperCase());
        return a >= m;
    }

    private static List<String> splitLines(String text) {
        List<String> result = new ArrayList<>();
        if (text == null) return result;
        for (String line : text.split("\n")) { String t = line.trim(); if (!t.isEmpty()) result.add(t); }
        return result;
    }

    private static boolean containsIgnoreCase(String haystack, String needle) {
        if (haystack == null || needle == null) return false;
        return haystack.toLowerCase().contains(needle.toLowerCase());
    }

    private static JSONObject prop(String type, String description) {
        return new JSONObject().put("type", type).put("description", description);
    }

    private static JSONObject emptySchema() {
        return new JSONObject().put("type", "object").put("properties", new JSONObject()).put("required", new JSONArray());
    }

    private static JSONObject tool(String name, String desc, JSONObject schema) {
        return new JSONObject().put("name", name).put("description", desc).put("inputSchema", schema);
    }

    private static JSONObject textContent(String text) {
        return new JSONObject().put("content", new JSONArray().put(new JSONObject().put("type", "text").put("text", text)));
    }

    private static JSONObject ok(Object id, JSONObject result) {
        return new JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", result);
    }

    private static JSONObject err(Object id, String msg) {
        return new JSONObject().put("jsonrpc", "2.0").put("id", id)
            .put("error", new JSONObject().put("code", -32000).put("message", msg != null ? msg : "error"));
    }

    private boolean auth(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Authorization");
        return h != null && h.equals("Bearer " + token);
    }

    private static void setCors(HttpExchange ex) {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin",  "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
    }

    private static String queryParam(String query, String key) {
        if (query == null) return null;
        for (String kv : query.split("&")) {
            String[] p = kv.split("=", 2);
            if (p.length == 2 && p[0].equals(key)) return p[1];
        }
        return null;
    }
}
