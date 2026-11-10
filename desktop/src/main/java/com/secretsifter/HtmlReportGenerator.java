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
            rows.append("  <td>").append(i + 1).append("</td>\n");
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
  <th onclick="sortBy(0)">#</th>
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
