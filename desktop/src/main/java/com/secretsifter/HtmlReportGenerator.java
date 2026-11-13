package com.secretsifter;

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
 *   - Summary stats in header (CRITICAL / HIGH / MEDIUM / LOW / INFO counts)
 *   - Severity filter buttons + domain / rule dropdowns + free-text search
 *   - Sortable columns (click header)
 *   - Color-coded severity + confidence badges
 *   - Values, URLs, and context snippets masked by default — toggle with eye buttons
 *   - Remediation guidance modal (⚠️ button)
 *   - Sticky filter bar
 *   - CSV + JSON export buttons (reads embedded data, no server round-trip)
 *   - No external dependencies — all CSS and JS embedded inline
 */
public final class HtmlReportGenerator {

    private HtmlReportGenerator() {}

    public static String generate(List<SecretFinding> findings, String target, String mode) {
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
            String dispVal   = maskValue(f.matchedValue());
            String ctxRaw    = f.context() != null ? trunc(f.context(), 120) : "";
            String ctx       = maskContext(ctxRaw);
            String urlFull   = f.sourceUrl() != null ? f.sourceUrl() : "";
            String domain    = extractDomain(urlFull);

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
            String rawEsc    = esc(f.matchedValue() != null ? f.matchedValue() : "");
            String maskedEsc = esc(dispVal);
            rows.append("  <td class=\"val-cell\" data-raw=\"").append(rawEsc)
                .append("\" data-masked=\"").append(maskedEsc)
                .append("\"><code>").append(maskedEsc).append("</code></td>\n");
            // Full URL as clickable link — display starts masked; href always full
            String urlMasked = maskUrl(urlFull);
            rows.append("  <td class=\"url-cell\" data-raw=\"").append(esc(urlFull))
                .append("\" data-masked=\"").append(esc(urlMasked)).append("\">")
                .append("<a href=\"").append(esc(urlFull))
                .append("\" target=\"_blank\" title=\"").append(esc(urlFull)).append("\">")
                .append(esc(urlMasked)).append("</a></td>\n");
            String targetFull = f.targetUrl() != null ? f.targetUrl() : "";
            rows.append("  <td>").append(esc(targetFull)).append("</td>\n");
            rows.append("  <td>").append(f.lineNumber()).append("</td>\n");
            rows.append("  <td class=\"ctx-cell\" data-raw=\"").append(esc(ctxRaw))
                .append("\" data-masked=\"").append(esc(ctx))
                .append("\"><code>").append(esc(ctx)).append("</code></td>\n");
            rows.append("  <td>").append(esc(f.validationLabel())).append("</td>\n");
            rows.append("</tr>\n");

            // ── JSON entry (embedded for client-side export) ───────────────
            jsonArr.append("{")
                .append("\"issueId\":\"").append(jsonEsc(f.issueId())).append("\",")
                .append("\"severity\":\"").append(jsonEsc(f.severity())).append("\",")
                .append("\"confidence\":\"").append(jsonEsc(f.confidence())).append("\",")
                .append("\"ruleId\":\"").append(jsonEsc(f.ruleId())).append("\",")
                .append("\"ruleName\":\"").append(jsonEsc(f.ruleName())).append("\",")
                .append("\"keyName\":\"").append(jsonEsc(f.keyName())).append("\",")
                .append("\"matchedValue\":\"").append(jsonEsc(f.matchedValue())).append("\",")
                .append("\"validation\":\"").append(jsonEsc(f.validationLabel())).append("\",")
                .append("\"domain\":\"").append(jsonEsc(domain)).append("\",")
                .append("\"sourceUrl\":\"").append(jsonEsc(urlFull)).append("\",")
                .append("\"targetUrl\":\"").append(jsonEsc(targetFull)).append("\",")
                .append("\"lineNumber\":").append(f.lineNumber()).append(",")
                .append("\"context\":\"").append(jsonEsc(f.context())).append("\"")
                .append("}");
        }
        jsonArr.append("]");

        String targetSection = (target != null && !target.isBlank())
                ? " &nbsp;|&nbsp; Target: " + esc(target)
                : "";
        return TEMPLATE
                .replace("{{TIMESTAMP}}",      esc(timestamp))
                .replace("{{TARGET_SECTION}}", targetSection)
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
        Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
        for (SecretFinding f : findings) {
            String domain = extractBaseDomain(f.sourceUrl());
            grouped.computeIfAbsent(domain, k -> new ArrayList<>()).add(f);
        }
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
        String clean = url;
        int hash = clean.indexOf('#');
        if (hash >= 0) clean = clean.substring(0, hash);
        if (clean.endsWith(" [HTML]")) clean = clean.substring(0, clean.length() - 7);
        String host;
        try {
            host = new java.net.URL(clean).getHost();
        } catch (Exception e) {
            return "unknown_domain";
        }
        if (host == null || host.isBlank()) return "unknown_domain";
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
    private static String maskContext(String ctx) {
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
    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                .replace("<",  "\\u003c")
                .replace(">",  "\\u003e");
    }

    /** Extract the hostname from a URL; strips display suffixes added by BulkScanPanel. */
    private static String extractDomain(String url) {
        if (url == null || url.isBlank()) return "";
        String clean = url;
        int hash = clean.indexOf('#');
        if (hash >= 0) clean = clean.substring(0, hash);
        if (clean.endsWith(" [HTML]")) clean = clean.substring(0, clean.length() - 7);
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
             align-items:flex-start;justify-content:center;padding-top:60px;overflow-y:auto}
.rem-overlay.open{display:flex}
.rem-modal{background:#fff;border-radius:10px;box-shadow:0 8px 32px rgba(0,0,0,.28);
           width:780px;max-width:92vw;overflow:hidden;animation:slideDown .2s ease;margin-bottom:40px}
@keyframes slideDown{from{opacity:0;transform:translateY(-18px)}to{opacity:1;transform:translateY(0)}}
.rem-modal-hdr{display:flex;align-items:center;gap:10px;background:#fff8f0;
               border-bottom:1px solid #ffe0b0;padding:14px 18px}
.rem-modal-title{font-weight:700;font-size:14px;color:#b45309;flex:1}
.rem-close{background:none;border:none;font-size:20px;color:#b45309;cursor:pointer;
           line-height:1;padding:0 2px}
.rem-close:hover{color:#7c2d12}
.rem-modal-body{padding:18px 22px 20px}
.rem-section-title{font-size:13px;font-weight:700;color:#fff;background:#b91c1c;
                   padding:7px 12px;border-radius:5px;margin:0 0 12px 0;letter-spacing:.02em}
.rem-section-title.general{background:#1d4ed8}
.rem-section{margin-bottom:20px}
.rem-section:last-child{margin-bottom:0}
.rem-modal-body ol{padding-left:20px;display:flex;flex-direction:column;gap:12px;margin:0}
.rem-modal-body ul{padding-left:18px;display:flex;flex-direction:column;gap:10px;margin:0}
.rem-modal-body li{font-size:12.5px;line-height:1.55;color:#444}
.rem-modal-body li strong{color:#1a1a2e}
.rem-modal-body li>ul{margin-top:6px;gap:6px}
.rem-modal-body li>ul>li{font-size:12px;color:#555}
.rem-modal-note{margin-top:14px;font-size:11px;color:#999;border-top:1px solid #f0f0f0;padding-top:10px}
.rem-divider{border:none;border-top:1px solid #e8e8e8;margin:18px 0}

/* ── Footer ──────────────────────────────────────────────────────────────── */
.footer{text-align:center;padding:20px;font-size:11px;color:#aaa}
</style>
</head>
<body>

<div class="hdr">
  <img class="hdr-icon" src="data:image/png;base64,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" alt="OWASP SecretSifter">
  <div>
    <h1>OWASP SecretSifter — Findings Report</h1>
    <p>Generated: {{TIMESTAMP}}{{TARGET_SECTION}} &nbsp;|&nbsp; Mode: {{MODE}} &nbsp;|&nbsp; Total findings: {{TOTAL}}</p>
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
      <span style="font-size:18px">&#9888;&#65039;</span>
      <span class="rem-modal-title">Remediation Guidance</span>
      <button class="rem-close" onclick="closeRem()" title="Close">&#10005;</button>
    </div>
    <div class="rem-modal-body">

      <!-- Section 1: Immediate Actions -->
      <div class="rem-section">
        <div class="rem-section-title">&#9888; Immediate Actions Required</div>
        <ol>
          <li>
            <strong>Rotate Exposed Azure Keys</strong>
            <ul>
              <li>Identify all Azure secrets currently exposed in the frontend code.</li>
              <li>Immediately rotate (invalidate and replace) these secrets to prevent unauthorized access.</li>
              <li>Store all new secrets securely in <strong>Azure Key Vault</strong> or an equivalent secure secrets management service.</li>
              <li>Update all application configurations to reference secrets from Azure Key Vault — not from code or environment variables exposed to the frontend.</li>
            </ul>
          </li>
          <li>
            <strong>Implement Backend For Frontend (BFF) Architecture</strong>
            <ul>
              <li>Refactor the application so that the frontend never directly accesses or stores secrets.</li>
              <li>All authentication flows and API calls that require secrets or sensitive credentials must be handled by a secure backend service (the BFF).</li>
              <li>The BFF should return only the necessary data to the frontend — not the secrets or tokens themselves.</li>
              <li>The frontend should only interact with the BFF, which will:
                <ul>
                  <li>Authenticate users as needed.</li>
                  <li>Generate and manage authorization tokens securely.</li>
                  <li>Call downstream APIs on behalf of the frontend, using secrets stored securely in the backend.</li>
                </ul>
              </li>
            </ul>
          </li>
          <li>
            <strong>Hardcoded Passwords</strong>
            <ul>
              <li>Remove all hardcoded passwords (user credentials or third-party credentials) from all frontend sources (JS files, HTML view-sources, API responses, etc.).</li>
              <li>Disable the exposed accounts — these should be assumed compromised.</li>
            </ul>
          </li>
        </ol>
      </div>

      <hr class="rem-divider">

      <!-- Section 2: General Remediation -->
      <div class="rem-section">
        <div class="rem-section-title general">&#128274; General Remediation</div>
        <ul>
          <li><strong>Rotate or revoke all identified credentials immediately</strong> — treat every exposed secret as compromised, even if no misuse has been observed yet.</li>
          <li><strong>Remove secrets from client-accessible assets</strong> — JavaScript files, HTML source, and API responses are readable by any user. Move credentials to server-side environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).</li>
          <li><strong>Audit git history</strong> — run <code>git log -S &lt;secret&gt;</code> to check whether the credential was ever committed. If so, rotate it and consider the entire history compromised.</li>
          <li><strong>Review how the secret was exposed</strong> — hardcoded value, SSR state blob, API response leakage, or webpack bundle inclusion each require a different fix at the source.</li>
          <li><strong>Notify affected service owners</strong> — check platform audit logs for any unauthorised access that may have already occurred using the exposed credential.</li>
        </ul>
        <div class="rem-modal-note">This guidance applies to all findings in this report. Rotate credentials before closing any associated tickets.</div>
      </div>

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
  <button class="fbtn rem" onclick="openRem()">&#9888;&#65039; Remediation</button>
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
  <th onclick="sortBy(6)">URL</th>
  <th onclick="sortBy(7)">Target</th>
  <th onclick="sortBy(8)">Line</th>
  <th>Context</th>
  <th onclick="sortBy(10)">Validation</th>
</tr>
</thead>
<tbody id="tbody">
{{ROWS}}
</tbody>
</table>
</div>

<div class="footer">
  OWASP SecretSifter &mdash; Live Credentials &amp; Secrets Scanner &nbsp;|&nbsp; Report generated {{TIMESTAMP}}
</div>

<!-- Embedded findings data for client-side CSV / JSON export -->
<script id="findings-data" type="application/json">{{JSON_DATA}}</script>

<script>
var currentSev = 'ALL';
var sortCol = -1, sortAsc = true;
var valsMasked = true;
var urlsMasked = true;
var ctxMasked  = true;

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
  var fields = ['severity','confidence','ruleId','ruleName','keyName','matchedValue','domain','sourceUrl','targetUrl','lineNumber','context'];
  var lines  = [fields.join(',')];
  data.forEach(function(f) {
    lines.push(fields.map(function(k) {
      return '"' + String(f[k] == null ? '' : f[k]).replace(/"/g, '""') + '"';
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
