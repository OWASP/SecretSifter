package com.secretscanner;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Generates a self-contained, sortable HTML report from a list of SecretFindings.
 *
 * Features:
 *   - Summary cards (HIGH / MEDIUM / LOW / INFO counts)
 *   - Severity filter buttons + domain / rule dropdowns + free-text search
 *   - Sortable columns (click header)
 *   - Color-coded severity badges
 *   - HIGH-severity values partially masked (first 4 + last 4 chars shown)
 *   - Full clickable URLs (open in new tab, copy from tooltip)
 *   - CSV + JSON export buttons (reads embedded data, no round-trip to Burp needed)
 *   - No external dependencies — all CSS and JS embedded inline
 */
public final class HtmlReportGenerator {

    private HtmlReportGenerator() {}

    public static String generate(List<SecretFinding> findings, String target, String mode) {
        return generate(findings, target, mode, false);
    }

    /**
     * @param redact when true the report never contains a raw secret: on-screen values, the
     *               "reveal" data attributes and the embedded JSON all carry the redacted value,
     *               and the secret is replaced in context lines. Issue IDs and fingerprints still
     *               identify each secret.
     */
    public static String generate(List<SecretFinding> findings, String target, String mode, boolean redact) {
        Map<String, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(
                        f -> f.severity().toUpperCase(), Collectors.counting()));

        long critCount   = counts.getOrDefault("CRITICAL", 0L);
        long highCount   = counts.getOrDefault("HIGH",   0L);
        long medCount    = counts.getOrDefault("MEDIUM", 0L);
        long lowCount    = counts.getOrDefault("LOW",    0L);
        long infoCount   = counts.getOrDefault("INFORMATION", 0L) + counts.getOrDefault("INFO", 0L);

        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder rows    = new StringBuilder();
        StringBuilder jsonArr = new StringBuilder("[");

        for (int i = 0; i < findings.size(); i++) {
            SecretFinding f = findings.get(i);
            if (i > 0) jsonArr.append(",");

            String sev       = esc(f.severity().toUpperCase());
            String sevLower  = f.severity().toLowerCase();
            String conf      = esc(f.confidence());
            String confLower = f.confidence().toLowerCase();
            String rawValue  = redact ? f.redactedValue() : f.matchedValue();
            String dispVal   = redact ? rawValue : maskValue(f.matchedValue());
            String ctxRaw    = f.context() != null ? trunc(f.context(), 120) : "";
            if (redact && f.matchedValue() != null && f.matchedValue().length() >= 4)
                ctxRaw = ctxRaw.replace(f.matchedValue(), "[REDACTED]");
            String ctx       = maskContext(ctxRaw, f.matchedValue());
            // In redact mode the naive replace above can miss a secret that trunc() split across the
            // 120-char window, leaving a partial secret in ctxRaw. ctxRaw feeds the table data-raw
            // attribute and the embedded JSON export, so collapse it to the fully-masked form.
            if (redact) ctxRaw = ctx;
            String urlFull    = f.sourceUrl() != null ? f.sourceUrl() : "";
            if (redact) urlFull = urlFull.replaceFirst("\\?[^ #]*", "?…");   // query strings can carry tokens
            String targetFull = f.targetUrl() != null ? f.targetUrl() : "";
            // Clean href: strip content-type labels and #inline-js / #json-script fragments
            // so the link navigates to the real URL, not to " [HTML]#inline-js" which 404s.
            String urlHref    = urlFull.replaceAll(" \\[(?:JSON|JS|HTML|XML|REQ-HEADERS|REQ-BODY)\\]", "")
                                       .replaceAll("#(?:inline-js|json-script|inline-json)$", "");
            String domain     = extractDomain(urlFull);

            // ── Table row ──────────────────────────────────────────────────
            rows.append("<tr data-sev=\"").append(sev)
                .append("\" data-domain=\"").append(esc(domain))
                .append("\" data-rule=\"").append(esc(f.ruleId()))
                .append("\">\n");
            rows.append("  <td><code>").append(esc(f.issueId())).append("</code></td>\n");
            rows.append("  <td><span class=\"badge sev-").append(sevLower).append("\">")
                .append(sev).append("</span></td>\n");
            rows.append("  <td><span class=\"badge conf-").append(confLower).append("\">")
                .append(conf).append("</span></td>\n");
            rows.append("  <td><code>").append(esc(f.ruleId())).append("</code></td>\n");
            rows.append("  <td><code>").append(esc(f.keyName())).append("</code></td>\n");
            String rawEsc    = esc(rawValue != null ? rawValue : "");
            String maskedEsc = esc(dispVal);
            rows.append("  <td class=\"val-cell\" data-raw=\"").append(rawEsc)
                .append("\" data-masked=\"").append(maskedEsc)
                .append("\"><code>").append(maskedEsc).append("</code></td>\n");
            // Source URL as clickable link — display starts masked; href always full
            String urlMasked = maskUrl(urlFull);
            rows.append("  <td class=\"url-cell\" data-raw=\"").append(esc(urlFull))
                .append("\" data-masked=\"").append(esc(urlMasked)).append("\">")
                .append("<a href=\"").append(esc(safeHref(urlHref)))
                .append("\" target=\"_blank\" title=\"").append(esc(urlFull)).append("\">")
                .append(esc(urlMasked)).append("</a></td>\n");
            // Target URL — the original input target from the bulk scan list
            String targetMasked = maskUrl(targetFull);
            rows.append("  <td class=\"url-cell\" data-raw=\"").append(esc(targetFull))
                .append("\" data-masked=\"").append(esc(targetMasked)).append("\">");
            if (!targetFull.isEmpty()) {
                rows.append("<a href=\"").append(esc(safeHref(targetFull)))
                    .append("\" target=\"_blank\" title=\"").append(esc(targetFull)).append("\">")
                    .append(esc(targetMasked)).append("</a>");
            }
            rows.append("</td>\n");
            rows.append("  <td>").append(f.lineNumber()).append("</td>\n");
            rows.append("  <td class=\"ctx-cell\" data-raw=\"").append(esc(ctxRaw))
                .append("\" data-masked=\"").append(esc(ctx))
                .append("\"><code>").append(esc(ctx)).append("</code></td>\n");
            rows.append("</tr>\n");

            // ── JSON entry (embedded for client-side export) ───────────────
            jsonArr.append("{")
                .append("\"issueId\":\"").append(jsonEsc(f.issueId())).append("\",")
                .append("\"occurrence\":\"").append(jsonEsc(f.occurrenceRef())).append("\",")
                .append("\"validation\":\"").append(jsonEsc(f.validationLabel())).append("\",")
                .append("\"fingerprint\":\"").append(jsonEsc(f.fingerprint())).append("\",")
                .append("\"severity\":\"").append(jsonEsc(f.severity())).append("\",")
                .append("\"confidence\":\"").append(jsonEsc(f.confidence())).append("\",")
                .append("\"ruleId\":\"").append(jsonEsc(f.ruleId())).append("\",")
                .append("\"ruleName\":\"").append(jsonEsc(f.ruleName())).append("\",")
                .append("\"keyName\":\"").append(jsonEsc(f.keyName())).append("\",")
                .append("\"matchedValue\":\"").append(jsonEsc(rawValue)).append("\",")
                .append("\"domain\":\"").append(jsonEsc(domain)).append("\",")
                .append("\"targetUrl\":\"").append(jsonEsc(targetFull)).append("\",")
                .append("\"sourceUrl\":\"").append(jsonEsc(urlFull)).append("\",")
                .append("\"lineNumber\":").append(f.lineNumber()).append(",")
                .append("\"context\":\"").append(jsonEsc(redact ? ctxRaw : f.context())).append("\"")
                .append("}");
        }
        jsonArr.append("]");

        String targetSegment = (target != null && !target.isBlank())
                ? " &nbsp;|&nbsp; Target: " + esc(target)
                : "";
        return TEMPLATE
                // branding first, so scanned content can never be read as one of these placeholders
                .replace("{{OWASP_LOGO_LIGHT}}", Branding.logoSvg(true))
                .replace("{{OWASP_LOGO_DARK}}",  Branding.logoSvg(false))
                .replace("{{OWASP_MARK_URI}}",   Branding.markDataUri())
                .replace("{{VERSION}}",          esc(SecretSifterVersion.VALUE))
                .replace("{{PROJECT_URL}}",      Branding.PROJECT_URL)
                .replace("{{TIMESTAMP}}",      esc(timestamp))
                .replace("{{TARGET_SEGMENT}}", targetSegment)
                .replace("{{MODE}}",           esc(mode != null ? mode : "—"))
                .replace("{{TOTAL}}",     String.valueOf(findings.size()))
                .replace("{{CRITICAL}}",  String.valueOf(critCount))
                .replace("{{HIGH}}",      String.valueOf(highCount))
                .replace("{{MEDIUM}}",    String.valueOf(medCount))
                .replace("{{LOW}}",       String.valueOf(lowCount))
                .replace("{{INFO}}",      String.valueOf(infoCount))
                .replace("{{ROWS}}",      rows.toString())
                .replace("{{JSON_DATA}}", jsonArr.toString());
    }

    /**
     * Groups findings by full hostname and returns one HTML string per host.
     * Key   = full hostname (e.g. "myinc.abc.com" or "unknown_domain").
     * Value = full self-contained HTML report for that host's findings.
     *
     * Findings whose sourceUrl cannot be parsed are grouped under "unknown_domain".
     * Insertion order is preserved so the ZIP entries appear alphabetically.
     */
    public static Map<String, String> generatePerDomain(List<SecretFinding> findings, String mode) {
        // Group by base domain preserving insertion order
        Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
        for (SecretFinding f : findings) {
            String domain = (f.targetUrl() != null && !f.targetUrl().isBlank())
                    ? extractBaseDomain(f.targetUrl())
                    : extractBaseDomain(f.sourceUrl());
            grouped.computeIfAbsent(domain, k -> new ArrayList<>()).add(f);
        }
        // Generate one HTML per domain group
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<SecretFinding>> entry : grouped.entrySet()) {
            String domain = entry.getKey();
            result.put(domain, generate(entry.getValue(), domain, mode));
        }
        return result;
    }

    /**
     * Extracts the full hostname from a URL for per-domain grouping.
     * Preserves subdomains so each distinct host gets its own report.
     * Examples:
     *   https://myinc.abc.com/v1/config.js    →  myinc.abc.com
     *   https://portal.clientB.com/app.js     →  portal.clientB.com
     *   https://10.0.0.5/test.js              →  10.0.0.5
     *   null / blank / unparseable            →  unknown_domain
     */
    private static String extractBaseDomain(String url) {
        if (url == null || url.isBlank()) return "unknown_domain";
        // Strip display suffixes and fragments added by BulkScanPanel
        String clean = url;
        int hash = clean.indexOf('#');
        if (hash >= 0) clean = clean.substring(0, hash);
        clean = clean.replaceAll(" \\[(?:JSON|JS|HTML|XML|REQ-HEADERS|REQ-BODY)\\]", "").trim();
        // Ensure a scheme is present — bare hostnames (user input without https://) fail URL parsing
        if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
            clean = "https://" + clean;
        }
        String host;
        try {
            host = new java.net.URL(clean).getHost();
        } catch (Exception e) {
            return "unknown_domain";
        }
        if (host == null || host.isBlank()) return "unknown_domain";
        // Return full hostname — subdomains preserved for distinct per-target reports
        return host.toLowerCase();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String maskValue(String val) {
        if (val == null) return "";
        if (val.length() > 10) {
            return val.substring(0, 4) + "••••••••" + val.substring(val.length() - 4);
        }
        return val;
    }

    /** Mask a URL completely — returns a fixed placeholder so no domain is visible. */
    private static String maskUrl(String url) {
        if (url == null || url.isBlank()) return "";
        return "••••••••••••";
    }

    /** Mask context snippet: show first 6 + last 6 chars with bullets in between. */
    private static String maskContext(String ctx, String matchedValue) {
        if (ctx == null) return "";
        if (ctx.length() > 14) {
            return ctx.substring(0, 6) + "••••••••••••" + ctx.substring(ctx.length() - 6);
        }
        return ctx;
    }

    private static String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 3) + "…" : s;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    /** JSON-safe escaping — also prevents </script> injection via \u003c. */
    /** Only http(s) URLs become clickable; anything else (javascript:, data:, ...) links nowhere. */
    private static String safeHref(String url) {
        if (url == null) return "#";
        String u = url.strip().toLowerCase(java.util.Locale.ROOT);
        return (u.startsWith("http://") || u.startsWith("https://")) ? url.strip() : "#";
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"'  -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '<'  -> sb.append("\\u003c");
                case '>'  -> sb.append("\\u003e");
                case '&'  -> sb.append("\\u0026");
                default -> {
                    // other control characters and the JS line separators would break JSON.parse
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    /** Extract the hostname from a URL; strips display suffixes added by BulkScanPanel. */
    private static String extractDomain(String url) {
        if (url == null || url.isBlank()) return "";
        String clean = url;
        int hash = clean.indexOf('#');
        if (hash >= 0) clean = clean.substring(0, hash);
        clean = clean.replaceAll(" \\[(?:JSON|JS|HTML|XML|REQ-HEADERS|REQ-BODY)\\]", "").trim();
        if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
            clean = "https://" + clean;
        }
        try {
            return new java.net.URL(clean).getHost();
        } catch (Exception e) {
            return "";
        }
    }

    // -------------------------------------------------------------------------
    // HTML template — fully self-contained (no CDN deps)
    // -------------------------------------------------------------------------

    private static final String TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OWASP SecretSifter Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#f0f2f5;color:#333;font-size:13px}

/* ── Header ─────────────────────────────────────────────────────────────── */
.hdr{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
     color:#fff;padding:18px 28px;display:flex;align-items:center;gap:16px}
.hdr-icon{width:48px;height:48px;flex-shrink:0}
.owasp-logo{display:inline-flex;align-items:center;flex-shrink:0}
.owasp-logo svg,.owasp-logo img{height:34px;width:auto;display:block}
.hdr .owasp-logo{padding-right:16px;margin-right:2px;border-right:1px solid rgba(255,255,255,.25)}
.footer .owasp-logo svg,.footer .owasp-logo img{height:18px;opacity:.75}
.footer .owasp-logo{vertical-align:middle;margin-right:8px}
.footer a{color:#888}
body::after{content:"";position:fixed;right:36px;bottom:36px;width:220px;height:200px;
     background:url("{{OWASP_MARK_URI}}") no-repeat center/contain;opacity:.05;pointer-events:none;z-index:9999}
@media print{body::after{opacity:.07}}
.hdr h1{font-size:20px;font-weight:700;letter-spacing:.3px}
.hdr p{font-size:11px;opacity:.65;margin-top:4px}
.hdr-stats{display:flex;gap:6px;margin-left:auto;align-items:center}
.hdr-sep{width:1px;height:40px;background:rgba(255,255,255,.15);margin-right:10px}
.hdr-stat{text-align:center;min-width:52px;padding:6px 10px;border-radius:8px;
          background:rgba(255,255,255,.07)}
.hdr-stat .num{font-size:22px;font-weight:800;line-height:1}
.hdr-stat .lbl{font-size:10px;opacity:.6;letter-spacing:.5px;text-transform:uppercase;margin-top:2px}
.hdr-stat.c .num{color:#d6bcfa}
.hdr-stat.h .num{color:#fc8181}
.hdr-stat.m .num{color:#f6ad55}
.hdr-stat.l .num{color:#f6e05e}
.hdr-stat.i .num{color:#63b3ed}

/* ── Filter bars ─────────────────────────────────────────────────────────── */
.filters{padding:10px 28px;background:#fff;border-bottom:1px solid #e0e0e0;
         display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.filters .lbl{font-size:11px;color:#888}
.fbtn{padding:4px 14px;border-radius:20px;border:none;cursor:pointer;
      font-size:12px;font-weight:600;letter-spacing:.3px;transition:opacity .15s}
.fbtn:hover{opacity:.8}
.fbtn.all{background:#eee;color:#333}
.fbtn.c{background:#e9d8fd;color:#553c9a}
.fbtn.h{background:#fed7d7;color:#c53030}
.fbtn.m{background:#feebc8;color:#c05621}
.fbtn.l{background:#fefcbf;color:#b7791f}
.fbtn.i{background:#bee3f8;color:#2b6cb0}
.fbtn.active{box-shadow:0 0 0 2px #333}
.fbtn.mask{background:#e9d8fd;color:#553c9a}
#maskBtn{margin-left:auto}
.fbtn.mask.unmasked{background:#553c9a;color:#fff}
.fbtn.exp{background:#c6f6d5;color:#276749;border-radius:6px;padding:4px 12px;margin-left:4px}
.fbtn.exp:hover{background:#9ae6b4}
/* Dropdowns + search input */
.fsel{padding:4px 8px;border:1px solid #ddd;border-radius:6px;
      font-size:12px;background:#fafafa;color:#333;cursor:pointer;max-width:180px}
.fsel:focus{outline:none;border-color:#a0aec0}
.fsearch{padding:4px 10px;border:1px solid #ddd;border-radius:6px;
         font-size:12px;background:#fafafa;color:#333;width:240px}
.fsearch:focus{outline:none;border-color:#a0aec0}
.fsearch::placeholder{color:#bbb}

/* ── Table ───────────────────────────────────────────────────────────────── */
.wrap{padding:16px 28px}
table{width:100%;border-collapse:collapse;background:#fff;
      border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
thead{background:#1a1a2e;color:#fff}
th{padding:10px 12px;text-align:left;font-size:12px;font-weight:600;
   letter-spacing:.4px;cursor:pointer;user-select:none;white-space:nowrap}
th:hover{background:#2d2d4e}
th.sort-asc::after{content:" ▲";font-size:9px}
th.sort-desc::after{content:" ▼";font-size:9px}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top;
   max-width:320px;word-break:break-word}
td:nth-child(1),td:nth-child(2),td:nth-child(3),td:nth-child(8){white-space:nowrap;max-width:none}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f7faff}
tr[data-sev="CRITICAL"]    td:first-child{border-left:3px solid #805ad5}
tr[data-sev="HIGH"]        td:first-child{border-left:3px solid #e53e3e}
tr[data-sev="MEDIUM"]      td:first-child{border-left:3px solid #dd6b20}
tr[data-sev="LOW"]         td:first-child{border-left:3px solid #d69e2e}
tr[data-sev="INFORMATION"] td:first-child{border-left:3px solid #3182ce}
code{background:#f4f4f4;padding:1px 5px;border-radius:3px;
     font-family:'Cascadia Code','Fira Code','Courier New',monospace;font-size:12px}
/* URL cell — full link, ellipsis on overflow, click opens in new tab */
.url-cell{font-size:11px;max-width:240px}
.url-cell a{color:#2b6cb0;text-decoration:none;display:block;
            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:240px}
.url-cell a:hover{text-decoration:underline;color:#1a365d}
.ctx-cell{font-size:11px;max-width:280px}
.val-cell code{word-break:break-all}
/* No-results banner */
#no-results{display:none;padding:28px;text-align:center;color:#888;font-size:13px;
            background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08)}

/* ── Badges ──────────────────────────────────────────────────────────────── */
.badge{display:inline-block;padding:2px 9px;border-radius:12px;
       font-size:10px;font-weight:700;letter-spacing:.4px;white-space:nowrap}
.sev-critical{background:#e9d8fd;color:#553c9a}
.sev-high{background:#fed7d7;color:#c53030}
.sev-medium{background:#feebc8;color:#c05621}
.sev-low{background:#fefcbf;color:#b7791f}
.sev-information,.sev-info{background:#bee3f8;color:#2b6cb0}
.conf-certain{background:#c6f6d5;color:#276749}
.conf-firm{background:#e9d8fd;color:#553c9a}
.conf-tentative{background:#e2e8f0;color:#4a5568}

/* ── Sticky filter bar ───────────────────────────────────────────────────── */
.sticky-bar{position:sticky;top:0;z-index:100;box-shadow:0 2px 6px rgba(0,0,0,.07)}
.sticky-bar .filters:last-child{border-bottom:1px solid #e0e0e0}

/* ── Remediation modal ───────────────────────────────────────────────────── */
.fbtn.rem{background:#fff3cd;color:#92400e;border:1px solid #f6c453;border-radius:6px;padding:4px 12px;margin-left:4px}
.fbtn.rem:hover{background:#ffe8a0}
.rem-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;
             align-items:flex-start;justify-content:center;padding-top:80px}
.rem-overlay.open{display:flex}
.rem-modal{background:#fff;border-radius:10px;box-shadow:0 8px 32px rgba(0,0,0,.28);
           width:640px;max-width:90vw;overflow:hidden;animation:slideDown .2s ease;
           display:flex;flex-direction:column;max-height:80vh}
@keyframes slideDown{from{opacity:0;transform:translateY(-18px)}to{opacity:1;transform:translateY(0)}}
.rem-modal-hdr{display:flex;align-items:center;gap:10px;background:#fff8f0;
               border-bottom:1px solid #ffe0b0;padding:14px 18px}
.rem-modal-title{font-weight:700;font-size:14px;color:#b45309;flex:1}
.rem-close{background:none;border:none;font-size:20px;color:#b45309;cursor:pointer;
           line-height:1;padding:0 2px}
.rem-close:hover{color:#7c2d12}
.rem-modal-body{padding:18px 22px 20px;overflow-y:auto;flex:1}
.rem-modal-body ul{padding-left:18px;display:flex;flex-direction:column;gap:8px}
.rem-modal-body ul ul{margin-top:6px;gap:5px}
.rem-modal-body li{font-size:12.5px;line-height:1.55;color:#444}
.rem-modal-body li strong{color:#1a1a2e}
.rem-modal-note{margin-top:14px;font-size:11px;color:#999;border-top:1px solid #f0f0f0;padding-top:10px}
.rem-section-title{font-size:13px;font-weight:700;margin:0 0 8px;padding:6px 10px;border-radius:5px}
.rem-section-title.urgent{background:#fef2f2;color:#b91c1c;border-left:3px solid #ef4444}
.rem-section-title.general{background:#f0f9ff;color:#0369a1;border-left:3px solid #38bdf8;margin-top:16px}
.rem-section{margin-bottom:4px}

/* ── Footer ──────────────────────────────────────────────────────────────── */
.footer{text-align:center;padding:20px;font-size:11px;color:#aaa}
</style>
</head>
<body>

<div class="hdr">
  <img class="hdr-icon" src="data:image/png;base64,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" alt="SecretSifter">
  <div>
    <h1>OWASP SecretSifter — Findings Report</h1>
    <p>Generated: {{TIMESTAMP}}{{TARGET_SEGMENT}}
       &nbsp;|&nbsp; Mode: {{MODE}} &nbsp;|&nbsp; Total findings: {{TOTAL}}</p>
  </div>
  <div class="hdr-stats">
    <div class="hdr-sep"></div>
    <div class="hdr-stat c"><div class="num">{{CRITICAL}}</div><div class="lbl">Critical</div></div>
    <div class="hdr-stat h"><div class="num">{{HIGH}}</div><div class="lbl">High</div></div>
    <div class="hdr-stat m"><div class="num">{{MEDIUM}}</div><div class="lbl">Medium</div></div>
    <div class="hdr-stat l"><div class="num">{{LOW}}</div><div class="lbl">Low</div></div>
    <div class="hdr-stat i"><div class="num">{{INFO}}</div><div class="lbl">Info</div></div>
  </div>
</div>

<!-- Remediation modal -->
<div class="rem-overlay" id="remOverlay" onclick="closeRemIfOutside(event)">
  <div class="rem-modal">
    <div class="rem-modal-hdr">
      <span style="font-size:18px">⚠️</span>
      <span class="rem-modal-title">Remediation Guidance</span>
      <button class="rem-close" onclick="closeRem()" title="Close">✕</button>
    </div>
    <div class="rem-modal-body">

      <!-- Section 1: Immediate Actions -->
      <div class="rem-section">
        <div class="rem-section-title urgent">&#x26A0;&#xFE0F; 1. Immediate Actions Required</div>
        <ul>
          <li><strong>Rotate Exposed Azure Keys:</strong>
            <ul>
              <li>Identify all Azure secrets (AppId, AppKey, Resource, Subscription Key, Secret Key, etc.) currently exposed in the frontend code.</li>
              <li>Immediately rotate (invalidate and replace) these secrets to prevent unauthorized access.</li>
              <li>Store all new secrets securely in <strong>Azure Key Vault</strong> or an equivalent secure secrets management service.</li>
              <li>Update all application configurations to reference the secrets from Azure Key Vault, not from code or environment variables exposed to the frontend.</li>
            </ul>
          </li>
          <li><strong>Implement Backend For Frontend (BFF) Architecture:</strong>
            <ul>
              <li>Refactor the application so that the frontend never directly accesses or stores secrets.</li>
              <li>All authentication flows and API calls that require secrets or sensitive credentials must be handled by a secure backend service (the BFF).</li>
              <li>The BFF should return only the necessary data to the frontend, not the secrets or tokens themselves.</li>
              <li>The frontend should only interact with the BFF, which will:
                <ul>
                  <li>Authenticate users as needed.</li>
                  <li>Generate and manage authorization tokens securely.</li>
                  <li>Call downstream APIs on behalf of the frontend, using the secrets stored securely in the backend.</li>
                </ul>
              </li>
            </ul>
          </li>
          <li><strong>Hardcoded Passwords:</strong>
            <ul>
              <li>Remove all hardcoded passwords (user creds or third party creds) on all frontend sources (JS files, HTML view-sources, API responses, etc.)</li>
              <li>Disable the exposed accounts — these should be assumed compromised.</li>
            </ul>
          </li>
        </ul>
      </div>

      <!-- Section 2: General Remediation -->
      <div class="rem-section">
        <div class="rem-section-title general">&#x1F6E1;&#xFE0F; 2. General Remediation</div>
        <ul>
          <li><strong>Rotate or revoke all identified credentials immediately</strong> — treat every exposed secret as compromised, even if no misuse has been observed yet.</li>
          <li><strong>Remove secrets from client-accessible assets</strong> — JavaScript files, HTML source, and API responses are readable by any user. Move credentials to server-side environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).</li>
          <li><strong>Audit git history</strong> — run <code>git log -S &lt;secret&gt;</code> to check whether the credential was ever committed. If so, rotate it and consider the entire history compromised.</li>
          <li><strong>Review how the secret was exposed</strong> — hardcoded value, SSR state blob, API response leakage, or webpack bundle inclusion each require a different fix at the source.</li>
          <li><strong>Notify affected service owners</strong> — check platform audit logs for any unauthorised access that may have already occurred using the exposed credential.</li>
        </ul>
      </div>

      <div class="rem-modal-note">This guidance applies to all findings in this report. Rotate credentials before closing any associated tickets.</div>
    </div>
  </div>
</div>

<div class="sticky-bar">
<!-- Row 1: severity filter + unmask -->
<div class="filters">
  <span class="lbl">Filter:</span>
  <button class="fbtn all active" onclick="setSev('ALL')">All</button>
  <button class="fbtn c" onclick="setSev('CRITICAL')">Critical</button>
  <button class="fbtn h" onclick="setSev('HIGH')">High</button>
  <button class="fbtn m" onclick="setSev('MEDIUM')">Medium</button>
  <button class="fbtn l" onclick="setSev('LOW')">Low</button>
  <button class="fbtn i" onclick="setSev('INFORMATION')">Info</button>
  <button id="maskBtn"    class="fbtn mask" onclick="toggleMask()"    title="Show or hide secret values"><span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Value</button>
  <button id="urlMaskBtn" class="fbtn mask" onclick="toggleUrlMask()" title="Show or hide full URLs"><span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> URL</button>
  <button id="ctxMaskBtn" class="fbtn mask" onclick="toggleCtxMask()" title="Show or hide context snippets"><span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Context</button>
</div>

<!-- Row 2: domain, rule, search, export -->
<div class="filters">
  <span class="lbl">Domain:</span>
  <select id="domainSel" class="fsel" onchange="applyAll()"><option value="">All domains</option></select>
  <span class="lbl">Rule:</span>
  <select id="ruleSel" class="fsel" onchange="applyAll()"><option value="">All rules</option></select>
  <input id="search" class="fsearch" type="text" placeholder="Search key / value / URL&#8230;" oninput="applyAll()">
  <button class="fbtn exp" onclick="exportCSV()">&#8595; CSV</button>
  <button class="fbtn exp" onclick="exportJSON()">&#8595; JSON</button>
  <button class="fbtn rem" onclick="openRem()">⚠️ Remediation</button>
</div>
</div>

<div class="wrap">
<div id="no-results">No findings match the current filter.</div>
<table id="tbl">
<thead>
<tr>
  <th onclick="sortBy(0)">Issue ID</th>
  <th onclick="sortBy(1)">Severity</th>
  <th onclick="sortBy(2)">Confidence</th>
  <th onclick="sortBy(3)">Rule ID</th>
  <th onclick="sortBy(4)">Key</th>
  <th>Value</th>
  <th onclick="sortBy(6)">Source URL</th>
  <th onclick="sortBy(7)">Target URL</th>
  <th onclick="sortBy(8)">Line</th>
  <th>Context</th>
</tr>
</thead>
<tbody id="tbody">
{{ROWS}}
</tbody>
</table>
</div>

<div class="footer">
  <span class="owasp-logo">{{OWASP_LOGO_DARK}}</span>OWASP SecretSifter v{{VERSION}} &nbsp;|&nbsp; An OWASP Foundation project
  &nbsp;|&nbsp; <a href="{{PROJECT_URL}}">{{PROJECT_URL}}</a> &nbsp;|&nbsp; Report generated {{TIMESTAMP}}
</div>

<!-- Embedded findings data for client-side CSV / JSON export -->
<script id="findings-data" type="application/json">{{JSON_DATA}}</script>

<script>
var currentSev = 'ALL';
var sortCol = -1, sortAsc = true;
var valsMasked = true;
var urlsMasked = true;

// ── Severity filter buttons ───────────────────────────────────────────────
function setSev(sev) {
  currentSev = sev;
  document.querySelectorAll('.fbtn').forEach(function(b) { b.classList.remove('active'); });
  event.target.classList.add('active');
  applyAll();
}

// ── Combined filter (severity + domain + rule + search) ───────────────────
function applyAll() {
  var domain = document.getElementById('domainSel').value;
  var rule   = document.getElementById('ruleSel').value;
  var q      = document.getElementById('search').value.toLowerCase();
  var visible = 0;
  document.querySelectorAll('#tbody tr').forEach(function(r) {
    var sevOk    = currentSev === 'ALL' || r.dataset.sev === currentSev;
    var domainOk = !domain || r.dataset.domain === domain;
    var ruleOk   = !rule   || r.dataset.rule   === rule;
    var qOk      = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
    var show     = sevOk && domainOk && ruleOk && qOk;
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.getElementById('no-results').style.display = visible === 0 ? 'block' : 'none';
  document.getElementById('tbl').style.display        = visible === 0 ? 'none'  : '';
}

// ── Populate domain + rule dropdowns from embedded row data ───────────────
function populateDropdowns() {
  var domains = [], rules = [];
  document.querySelectorAll('#tbody tr').forEach(function(r) {
    if (r.dataset.domain && domains.indexOf(r.dataset.domain) === -1) domains.push(r.dataset.domain);
    if (r.dataset.rule   && rules.indexOf(r.dataset.rule)     === -1) rules.push(r.dataset.rule);
  });
  domains.sort();
  rules.sort();
  var dSel = document.getElementById('domainSel');
  domains.forEach(function(d) {
    var o = document.createElement('option'); o.value = d; o.textContent = d; dSel.appendChild(o);
  });
  var rSel = document.getElementById('ruleSel');
  rules.forEach(function(r) {
    var o = document.createElement('option'); o.value = r; o.textContent = r; rSel.appendChild(o);
  });
}

// ── Mask / Unmask ─────────────────────────────────────────────────────────
function toggleMask() {
  valsMasked = !valsMasked;
  document.querySelectorAll('.val-cell').forEach(function(td) {
    var code = td.querySelector('code');
    if (code) code.textContent = valsMasked ? (td.dataset.masked || '') : (td.dataset.raw || '');
  });
  var btn = document.getElementById('maskBtn');
  btn.innerHTML = valsMasked
    ? '<span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Value'
    : '&#128065; Value';
  btn.classList.toggle('unmasked', !valsMasked);
}

function toggleUrlMask() {
  urlsMasked = !urlsMasked;
  document.querySelectorAll('.url-cell').forEach(function(td) {
    var a = td.querySelector('a');
    if (a) a.textContent = urlsMasked ? (td.dataset.masked || '') : (td.dataset.raw || '');
  });
  var btn = document.getElementById('urlMaskBtn');
  btn.innerHTML = urlsMasked
    ? '<span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> URL'
    : '&#128065; URL';
  btn.classList.toggle('unmasked', !urlsMasked);
}

var ctxMasked = true;
function toggleCtxMask() {
  ctxMasked = !ctxMasked;
  document.querySelectorAll('.ctx-cell').forEach(function(td) {
    var code = td.querySelector('code');
    if (code) code.textContent = ctxMasked ? (td.dataset.masked || '') : (td.dataset.raw || '');
  });
  var btn = document.getElementById('ctxMaskBtn');
  btn.innerHTML = ctxMasked
    ? '<span style="text-decoration:line-through;text-decoration-thickness:2px">&#128065;</span> Context'
    : '&#128065; Context';
  btn.classList.toggle('unmasked', !ctxMasked);
}

function openRem()  { document.getElementById('remOverlay').classList.add('open'); }
function closeRem() { document.getElementById('remOverlay').classList.remove('open'); }
function closeRemIfOutside(e) { if (e.target === document.getElementById('remOverlay')) closeRem(); }
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeRem(); });

// ── Column sort ───────────────────────────────────────────────────────────
function sortBy(col) {
  var ths = document.querySelectorAll('thead th');
  ths.forEach(function(th) { th.classList.remove('sort-asc','sort-desc'); });
  if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
  ths[col].classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
  var tbody = document.getElementById('tbody');
  var rows  = Array.from(tbody.querySelectorAll('tr'));
  rows.sort(function(a, b) {
    var av = a.cells[col] ? a.cells[col].innerText.trim() : '';
    var bv = b.cells[col] ? b.cells[col].innerText.trim() : '';
    if (!isNaN(av) && !isNaN(bv)) { av = +av; bv = +bv; }
    if (av < bv) return sortAsc ? -1 : 1;
    if (av > bv) return sortAsc ?  1 : -1;
    return 0;
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
}

// ── Export ────────────────────────────────────────────────────────────────
function exportJSON() {
  var data = document.getElementById('findings-data').textContent;
  trigger(new Blob([data], {type: 'application/json'}), 'secret-findings-' + Date.now() + '.json');
}

function exportCSV() {
  var data   = JSON.parse(document.getElementById('findings-data').textContent);
  var fields = ['issueId','occurrence','fingerprint','severity','confidence','ruleId','ruleName','keyName','matchedValue','domain','targetUrl','sourceUrl','lineNumber','context'];
  var lines  = [fields.join(',')];
  data.forEach(function(f) {
    lines.push(fields.map(function(k) {
      var v = String(f[k] == null ? '' : f[k]);
      var c = v.charCodeAt(0);
      // stop spreadsheet apps treating a scanned value as a formula
      if ('=+-@'.indexOf(v.charAt(0)) >= 0 || c === 9 || c === 13) v = "'" + v;
      return '"' + v.replace(/"/g, '""') + '"';
    }).join(','));
  });
  trigger(new Blob([lines.join('\\n')], {type: 'text/csv'}), 'secret-findings-' + Date.now() + '.csv');
}

function trigger(blob, filename) {
  var url = URL.createObjectURL(blob);
  var a   = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
}

document.addEventListener('DOMContentLoaded', populateDropdowns);
</script>
</body>
</html>
""";
}
