# Changelog

All notable changes to SecretSifter Burp MCP are documented here.

## [1.0.0] — 2026-04-26

### Initial public release

SecretSifter Burp MCP is the **full edition** of the SecretSifter Burp Suite extension.
It includes the same scanning core as the [BApp Store edition](https://github.com/secretsifter/secretsifter-burp)
plus AI Triage and a Model Context Protocol (MCP) server for Claude Code integration.

**MCP / AI features (this edition only)**

- **Multi-provider AI Triage** — Settings → AI Triage tab lets you choose between Burp AI (built-in, Pro only), Anthropic API (BYO key), and OpenAI / compatible (BYO key + endpoint, supports self-hosted Ollama / LM Studio). All three providers support per-finding triage (right-click) and bulk *AI Triage All*.
- **Deterministic severity overrides** — after AI confirms a finding is real, vendor-specific key names get a deterministic severity bump (`AppKey*` → CRITICAL, `ResourceKey*` / `SubscriptionKey*` → HIGH, `AppId` → INFORMATION, JWT in JSON API responses → CRITICAL).
- **Noise review dialog** — AI-flagged false positives are highlighted amber in the table and surface in a review dialog with reasoning per finding; user picks which to delete or keep.
- **Batch prompt efficiency** — Anthropic and OpenAI providers send up to 15 findings per API call, reducing latency and API cost for bulk triage.
- **Cancel AI Triage** — clicking the cancel button (when an AI batch is mid-flight) immediately unblocks the wait thread, including the long-running MCP wait.
- **MCP server** (`127.0.0.1:8765`, loopback only) — JSON-RPC server so Claude Code or any MCP-compatible AI agent can drive the scanner programmatically: start scans, fetch findings, export reports, and submit triage results back to the table.
  - `secretsifter_get_triage_request` — Claude Code pulls a batch of findings to triage
  - `secretsifter_submit_triage_results` — Claude Code submits its verdicts; UI updates live
  - `secretsifter_get_findings`, `secretsifter_get_findings_csv`, `secretsifter_get_findings_html` — read-only finding access
  - `secretsifter_scan_url`, `secretsifter_scan_bulk` — initiate scans
  - `secretsifter_get_scan_status`, `secretsifter_stop_scan`, `secretsifter_clear_findings` — scan lifecycle

**Scanning core (shared with BApp Store edition)**

- **Passive scanning** — registers a `ScanCheck` with Burp's Scanner API (Pro); fires on every proxied response. Sitemap sweep on load scans all existing site-map responses immediately.
- **Active scanning** — right-click context menu "Rescan for Secrets" in Proxy History, Repeater, Logger, Site Map. Optional HTML report export.
- **Bulk Scan tab** — paste/import URL lists (`.txt`, `.csv`, `.har`); follows `<script src>` and webpack chunks; Scope Monitor for passive proxy capture; Headless Browse via Chrome/Chromium for dynamic JS capture; 1–50 concurrent worker threads.
- **160+ detection rules**: 100+ format-anchored vendor token patterns (GitHub, GitLab, AWS, Stripe, OpenAI, Anthropic, Slack, Shopify, Azure, GCP, Discord, Telegram, Mailgun, etc.) + 40+ context-gated rules (Algolia, Cloudflare, Salesforce, Auth0, Supabase, etc.) + entropy-based scanner + generic KV scanner + JSON deep walker + DB connection strings + URL-embedded credentials + PII (SSN + Luhn-validated credit cards).
- **Scan tiers** — FAST / LIGHT / FULL trade speed for coverage.
- **JWT intelligence** — Bearer header JWTs suppressed by default; JWTs in API token-issuance responses upgraded to HIGH.
- **Custom regex rules** — import `Rule Name | regex | severity` lines via Settings → Custom Rules. Optional **Custom rules only (raw)** mode skips built-in scanners and FP filters and reports every regex match.
- **NOISE marking** — Severity / Confidence dropdowns include `NOISE` to gray out rows and exclude from exports.
- **Exports** — HTML report (all-in-one) + Per-Domain ZIP (one HTML per host) + CSV + Target Status CSV.
- **Settings** — entropy threshold, PII toggle, request header scanning, CDN blocklist, key name blocklist / allowlist (all persisted via Burp's `Preferences` API).
- **False-positive engineering** — homogeneity check, session identifier suppression, PEM header-only suppression, opaque Bearer suppression, structural key suffix filter, JS code-fragment guard, webpack content-hash suppression, UUID rejection in entropy scanner, and 60+ noise key filter.

**Architecture**

- Java 17, Montoya API 2024.7+, Gradle 8.9 with `com.gradleup.shadow` 8.3.5
- Single-JAR distribution: `secretsifter-mcp-<version>.jar` (~580 KB)
- Reproducible build (`preserveFileTimestamps = false`, `reproducibleFileOrder = true`) — anyone cloning the repo and running `./gradlew shadowJar` produces a byte-identical artifact
- Stateless scanner core (`scanText()` is safe for concurrent calls)
- Background thread pools for scan workers and AI triage; clean unloading on extension reload
- macOS EDT fix for sitemap sweep (silent empty-list bug on macOS)
- Cross-platform Chrome detection (macOS / Windows / Linux)
- Dependencies bundled in JAR: Gson 2.10.1 (Apache 2.0). Montoya API + JUnit 5 are `compileOnly` / `testImplementation` only (not bundled).

**Compatibility**

- Burp Suite Professional 2024.7+ (full functionality including Dashboard issue reporting)
- Burp Suite Community 2024.7+ (Bulk Scan, proxy handler, context menu rescan, AI Triage, MCP server — passive scan check skipped)
- Java 17+ (bundled with Burp)
- macOS, Windows, Linux

**Network communications**

The extension makes outbound calls only when the user explicitly triggers them: Bulk Scan
fetches user-pasted URLs through the user's Burp proxy; Headless Browse launches Chrome to
the user's URLs through the user's Burp proxy; AI Triage providers (Anthropic / OpenAI)
send finding fields to user-configured API endpoints with user-provided keys. The MCP server
binds **loopback only** (127.0.0.1:8765) — no inbound from the network. No telemetry, no
auto-update, no phone-home.
