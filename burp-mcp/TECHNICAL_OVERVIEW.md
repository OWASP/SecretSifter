# SecretSifter — Technical Architecture & Detection Reference

> A deep-dive reference for understanding exactly how SecretSifter is built,
> what it detects, and why each layer exists.

---

## 1. What It Is

SecretSifter is a **Burp Suite extension** (Java, Montoya API) that passively and
actively scans HTTP traffic for exposed secrets, credentials, API keys, connection
strings, and PII. It ships as a single shadow JAR (~430 KB) and runs inside the
Burp JVM — no external processes, no internet calls.

---

## 2. Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Build | Gradle 8 (`shadowJar` — fat JAR with all deps bundled) |
| Burp API | Montoya API (2024.7+) — replaces the old Extender/IBurpExtender API |
| JSON parsing | Google Gson (Apache 2.0) — used in the JSON deep-walker |
| UI | Java Swing (via Montoya's `registerSuiteTab`) |
| Persistence | Burp's `Preferences` API (`ss.*` key namespace) |
| Threading | Java `ExecutorService` (bulk scan) + `ThreadLocal` (per-URL target context) |

---

## 3. Source Files

```
src/main/java/com/secretscanner/
  SecretScannerExtension.java  — Burp entry point, wires all components
  SecretScanner.java           — Core scan engine (stateless, thread-safe)
  Patterns.java                — All compiled regex constants + rule tables
  ScanSettings.java            — Thread-safe settings model (volatile fields)
  BulkScanPanel.java           — Bulk scan UI tab (URL import, threading, reports)
  SettingsPanel.java           — Settings UI tab
  SecretScanCheck.java         — Passive scan check (Burp Pro only)
  SecretProxyHandler.java      — Proxy response handler (all traffic, incl. cross-origin)
  SecretContextMenu.java       — Right-click "Rescan for Secrets" context menu
  SecretFinding.java           — Immutable finding record (ruleId, value, severity, etc.)
  HtmlReportGenerator.java     — HTML + per-domain ZIP report generator
```

---

## 4. Extension Initialization (Burp Entry Point)

`SecretScannerExtension.initialize(MontoyaApi api)` runs once at load time and
wires six components in order:

```
1. ScanSettings           ← loads from Burp Preferences (persisted across sessions)
2. SecretScanner          ← stateless engine; takes settings as injected dependency
3. SecretScanCheck        ← registers as passive scan check (Pro only; silently skipped in Community)
4. SecretProxyHandler     ← fires on every proxy response (not scope-limited)
5. SecretContextMenu      ← "Rescan for Secrets" in Proxy History / Repeater
6. BulkScanPanel +
   SettingsPanel          ← single "Secret Sifter" top-level tab with two sub-tabs
7. Sitemap sweep          ← at startup, rescans all JS/HTML already in Burp's site map
```

---

## 5. Scan Entry Points

There are four ways a URL or response gets scanned:

| Entry Point | How It Triggers | Scope |
|---|---|---|
| **Passive scan check** (`SecretScanCheck`) | Every proxied response, via Burp's scanner API | In-scope only (Burp Pro) |
| **Proxy handler** (`SecretProxyHandler`) | Every proxy response synchronously | All traffic, cross-origin aware |
| **Context menu rescan** | User right-clicks in Proxy History / Repeater → "Rescan for Secrets" | Selected host |
| **Bulk scan** (`BulkScanPanel`) | User pastes/imports URL list; up to 50 concurrent threads | User-specified URLs |

The **proxy handler** also implements **Scope Monitor**: if a watched host receives
a response containing XHR/Fetch calls to other domains, those cross-origin API
responses are routed into the Bulk Scan table using the `Referer`/`Origin` header.

---

## 6. Scan Tiers

Three tiers trade speed vs. coverage. Configurable in Settings or the Bulk Scan tab.

| Tier | Phases Active | Best For |
|---|---|---|
| **FAST** | Anchored vendor tokens + URL credentials | Quick recon, large site maps, CI speed |
| **LIGHT** | FAST + DB connection strings + 40+ context-gated rules | Standard pentest engagement |
| **FULL** | LIGHT + Generic KV + SSR blobs + High-entropy scanner + Getter functions + JSON deep walk + XML leaves + PII | Deep audit, bug bounty |

---

## 7. The Scan Pipeline

Every response body flows through `SecretScanner.scanText()`. The phases run in
strict order; later phases only run at the appropriate tier.

```
scanText(body, contentType, url)
│
├── [Pre-pass A] Form-encoded decode
│     If Content-Type: application/x-www-form-urlencoded → parse key=value pairs,
│     check each key against isSemanticSecretKey() + isProbableSecretValue()
│
├── [Pre-pass B] HTML inline script extraction  (HTML only)
│     Extract every <script> block (no src attr) → recurse with JS content-type
│     Extract <script type="application/json"> → recurse with JSON content-type
│
├── [Pre-pass C] Request headers blob  (when URL ends in [REQ-HEADERS])
│     Parse "Name: Value\n" lines → apply KNOWN_SECRET_HEADERS + isSemanticSecretKey check
│
├── Phase 1 — Anchored vendor tokens  (ALL tiers)
│     Iterate ANCHORED_RULES (100+ patterns) → emit finding per unique match
│
├── Phase 2 — URL credentials  (ALL tiers)
│     URL_WITH_CREDS  → https://user:pass@host
│     URL_QUERY_CREDS → https://host/path?password=X
│
├── Custom rules  (ALL tiers — user-defined regexes from Settings)
│
├── [FAST → return here]
│
├── Phase 3 — DB connection strings  (LIGHT + FULL)
│     DB_CONN_STRING  → mongodb/postgres/mysql/redis/amqp URI with credentials
│     DOTNET_CONN_STR → ADO.NET/SQL Server semicolon-delimited "Password=X" format
│
├── Phase 3b — Context-gated rules  (LIGHT + FULL)
│     CONTEXT_GATED_RULES (40+ rules) — keyword proximity required
│
├── [LIGHT → return here]
│
├── Phase 4 — Generic KV scanner  (FULL, non-HTML bodies)
│     GENERIC_KV regex → key=value pairs; gates: isSemanticSecretKey + isProbableSecretValue
│
├── Phase 5 — SSR state blobs  (FULL)
│     window.__NEXT_DATA__, __REDUX_STATE__, __CONFIG__, window.appConfig, etc.
│     <script type="application/json"> tags
│     → extracts embedded JSON → walkJsonBody()
│
├── Phase 6 — High-entropy scanner  (FULL)
│     Quoted strings 20–512 chars → Shannon entropy > threshold → context keyword proximity check
│
├── Phase 7 — Getter function scanner  (FULL, JS only)
│     Arrow functions + named functions returning string literals → semantic key name gate
│
├── Phase 8 — JSON deep walker  (FULL, JSON Content-Type)
│     Gson parse → depth-first walk to depth 20 → checkJsonLeaf() on every string value
│
├── Phase 9 — XML leaf scanner  (FULL, XML Content-Type)
│     XML_ELEMENT pattern → tag/value pairs → same gates as JSON walker
│
└── Phase 10 — PII  (FULL, when piiEnabled = true)
      SSN: format regex + SSN_CONTEXT keyword in surrounding 3 lines
      Credit card: CC_CANDIDATE format + Luhn validation + numeric context guards
```

---

## 8. Detection Layers — Full Breakdown

### 8.1 Layer 1: Anchored Vendor Token Rules (`ANCHORED_RULES`)

**What:** Format-anchored patterns with fixed prefixes or structures that
unambiguously identify a specific vendor's token. Near-zero false positive rate.

**How:** Every pattern is `\b`-word-boundary anchored with exact prefix + length
constraints. Compiled once at class-load time. Run at **all tiers**.

**Rule count:** 100+ patterns covering:

| Vendor Group | Patterns |
|---|---|
| **Source control** | GitHub (PAT classic/OAuth/Actions/Refresh/Fine-grained), GitLab (PAT + Deploy), NPM |
| **Chat / Messaging** | Slack (Bot/User/App/Config tokens + Webhook URL), Discord (Bot token + Webhook), Telegram bot, Teams Webhook |
| **Payments** | Stripe (Live/Test secret + Restricted + Publishable + Webhook secret), Shopify (Admin/Custom/Secret), HubSpot, WooCommerce, Flutterwave, Square, Razorpay (Live + Test), Braintree, Paystack, Klaviyo |
| **Email / Comms** | SendGrid, Mailchimp, Mailgun, Sendinblue/Brevo, Shippo, Duffel, EasyPost |
| **AI / ML** | OpenAI (sk- + sk-proj-), Anthropic, Groq, Replicate, xAI/Grok, Hugging Face, LangSmith, Langfuse, Mistral, Cohere |
| **Cloud / Infra** | AWS Access Key ID (AKIA/ASIA/AROA/AIDA), Google API Key (AIza), Mapbox (pk.eyJ/sk.eyJ), Firebase FCM, GCP service account email, GCP OAuth2 (ya29.), Azure Storage connection string, Azure App Insights connection string, Azure IoT Hub, Azure Event Hub, Azure Cosmos DB, Azure Redis, Azure Communication Services, Azure Web PubSub, Azure SignalR |
| **DevOps / CI-CD** | HashiCorp Vault (hvs. + legacy s.), Pulumi, Terraform Cloud (at.), CircleCI, Buildkite, Tailscale, Fly.io, Doppler, Scalingo, Okta SSWS |
| **Other SaaS** | Twilio SID (AC/SK/FO/FW/AT prefixes), Databricks (dapi), Airtable, Netlify, Contentful, DigitalOcean, PlanetScale, Postman, Notion (old + new), PyPI, Rubygems, Sentry, Figma, Dropbox, 1Password, Harness, Adafruit IO, SonarQube, GitHub OAuth Client ID (apps.googleusercontent.com), Elastic API key, Asana PAT, Apify, Linear, New Relic, Dynatrace, PagerDuty, Age encryption key, Alibaba Cloud, Atlassian, CFPAT (Contentful), Grafana |
| **Crypto / Security** | PEM Private Key header + body, bcrypt hash, WireGuard |
| **Webhooks / Misc** | Discord webhook URL, Slack webhook URL, Twitter/X bearer, Cloudinary URL, JWT (gated), Azure SAS, AWS Access Key ID variants |

---

### 8.2 Layer 2: Context-Gated Rules (`CONTEXT_GATED_RULES`)

**What:** Rules where the token format alone is too generic (e.g., a 32-hex string).
A keyword **must appear within ~60–80 chars** of the value to confirm vendor context.

**How:** Each `CtxRule` has a pattern that includes the keyword as part of the regex
(not a separate proximity check). Runs at **LIGHT + FULL** tiers.

**Rule count:** 40+ rules covering:

| Vendor | Rule ID | What It Catches |
|---|---|---|
| AWS | AWS_KEY_002 | AWS Secret Access Key (40-char base62 after `aws_secret` keyword) |
| Azure DevOps | AZURE_DEVOPS_KEY_001 | PAT near `azure devops` / `dev.azure.com` / `vsts` (52–84 char base64) |
| Snowflake | SNOWFLAKE_KEY_001 | Password/token near `snowflake` keyword |
| Jira | JIRA_KEY_001 | 24-char base64 near `jira` / `atlassian.net` keyword |
| Salesforce | SALESFORCE_KEY_001 | `00D{orgId}!{token}` format near `salesforce` keyword |
| Datadog | DATADOG_KEY_001 | 32–40 hex after `DD_API_KEY` / `DD_APP_KEY` |
| Heroku | HEROKU_KEY_001 | UUID near `heroku` keyword |
| LaunchDarkly | LAUNCHDARKLY_KEY_001 | `sdk-` prefix near `launchdarkly` keyword |
| MessageBird | MESSAGEBIRD_KEY_001 | 25 alnum near `messagebird` keyword |
| Splunk | SPLUNK_KEY_001 | UUID near `splunk` / `HEC_TOKEN` |
| Twilio | TWILIO_AUTH_001 | 32 lowercase hex after `twilio...auth_token` keyword |
| Webex | WEBEX_KEY_001 | 85+ char token near `webex...token` keyword |
| Azure APIM | AZURE_APIM_001 | 32–64 alnum after `Ocp-Apim-Subscription-Key` header |
| Azure APIM | AZURE_APIM_002 | 20–60 char client secret near `apim_secret_key` / `azure_client_secret` |
| Azure APIM | AZURE_APIM_003 | UUID near `apim_client_id` / `aad_client_id` |
| Azure APIM | AZURE_APIM_004 | APIM subscription key stored as env config variable |
| Azure App Insights | AZURE_APPINSIGHTS_001 | UUID instrumentation key near `InstrumentationKey` keyword |
| Azure SAS | AZURE_SAS_001 | Base64 token after `SharedAccessSignature` / `sig=` keyword |
| Algolia | ALGOLIA_KEY_001/002 | App ID (10 uppercase) + API key (32 hex) near `algolia` keyword |
| Cloudflare | CLOUDFLARE_KEY_001 | 40-char base62url near `cloudflare` / `CF_API_TOKEN` |
| Zendesk | ZENDESK_KEY_001 | 40 alnum near `zendesk` keyword |
| Zoom | ZOOM_KEY_001 | 24–32 alnum secret near `zoom...secret` keyword |
| Intercom | INTERCOM_KEY_001 | 64 alnum token near `intercom` keyword |
| Auth0 | AUTH0_KEY_001 | 32–80 char value after `AUTH0_CLIENT_SECRET` |
| Jenkins | JENKINS_KEY_001 | 32–36 hex near `jenkins...token` keyword |
| DroneCI | DRONECI_KEY_001 | 32–64 hex near `drone...token` keyword |
| Travis CI | TRAVISCI_KEY_001 | 22-char uppercase near `travis...token` keyword |
| Vercel | VERCEL_KEY_001 | 24 uppercase alnum near `vercel...token` keyword |
| Freshdesk | FRESHDESK_KEY_001 | 20–40 alnum near `freshdesk` keyword |
| Monday.com | MONDAY_KEY_001 | JWT near `monday` keyword |
| Coinbase | COINBASE_KEY_001 | 32 lowercase alnum near `coinbase` keyword |
| PayPal | PAYPAL_KEY_001 | `A` + 78–99 uppercase near `paypal...client_id` |
| IBM Cloud | IBM_KEY_001 | 42–44 alnum near `ibm` / `bx` keyword |
| Cohere | COHERE_KEY_001 | 40 alnum near `cohere` keyword |
| Mistral AI | MISTRAL_KEY_001 | 32 alnum near `mistral` keyword |
| Spotify | SPOTIFY_KEY_001 | 100+ opaque token near `spotify` keyword |
| SonarQube | SONAR_KEY_002 | 40 hex near `sonar...token` keyword |
| Snyk | SNYK_KEY_001 | UUID (uppercase) near `snyk...token` keyword |
| WireGuard | WIREGUARD_KEY_001 | Base64 after `PrivateKey =` |
| HashiCorp Vault | VAULT_TOKEN_002 | `s.` + 24–128 base62 near `vault` keyword (legacy token) |
| GCP | GCP_KEY_002 | Presence of `"auth_provider_x509_cert_url"` field (service account JSON) |
| Kubernetes | K8S_KEY_001 | `{6alnum}.{16alnum}` bootstrap token format near `token` keyword |
| CryptoJS | CRYPTOJS_KEY_001 | Base64 passphrase near `cryptojs_secret_key` variable name |
| CryptoJS | CRYPTOJS_CALLSITE_001 | Inline key string in `CryptoJS.AES.encrypt/decrypt(ciphertext, "key")` |
| CryptoJS | CRYPTOJS_BLOB_001 | Value starting with `U2FsdGVkX1` (AES-encrypted blob) |
| GUID/Token | GUID_TOKEN_001 | UUID where key name ends in `Token(s)` or `Secret(s)` |

---

### 8.3 Layer 3: Database / Broker Connection Strings

**What:** URIs and ADO.NET-style strings with embedded credentials.

**Runs at:** LIGHT + FULL

**Patterns:**
- `DB_CONN_STRING` — URI format: `mongodb/postgresql/postgres/mysql/mssql/redis/amqp(s)/jdbc:*://user:pass@host`
- `DOTNET_CONN_STR` — Semicolon key=value format: `Data Source=host;...;Password=secret`
- `AZURE_CONN_STR` — `DefaultEndpointsProtocol=https;AccountName=X;AccountKey=Y` (anchored)

---

### 8.4 Layer 4: Generic Key-Value Scanner (`GENERIC_KV`)

**What:** Catches any `key="value"` or `key: "value"` pair where the key is
semantically a secret holder and the value looks like a real credential.

**Runs at:** FULL only (non-HTML bodies — HTML is scanned via inline script extraction)

**Gates applied in order:**
1. `isForcedNoiseKey(key)` — exact-match reject against 90+ known noise key names
2. `NOISE_KEYNAMES.matcher(key).matches()` — regex reject for UI/label/endpoint keys
3. Webpack/Angular module manifest key check (e.g. `src_app_..._module_ts`)
4. `isSemanticSecretKey(key)` — compound key semantic analysis (see §9.1)
5. `isApiOverrideKey(key)` — high-confidence exact key name list (e.g. `inviteApiKey`)
6. `isPlaceholder(val)` — reject dummy values
7. GUID gate: UUID values only pass if `isAzureCredentialKey(key)` is true
8. `isProbableSecretValue(val)` — reject pure-alpha, too-short, common words
9. `isJwt(val)` — suppress JWT values (session tokens, not hardcoded secrets)
10. `BLOCKCHAIN_HASH_KEY` guard — reject tx/wallet/eth key names

---

### 8.5 Layer 5: High-Entropy Scanner

**What:** Finds any quoted string 20–512 chars that has high Shannon entropy
**and** appears within ±80 chars of a semantic context keyword.

**Runs at:** FULL

**How it works:**
1. Match `QUOTED_LONG_VALUE` pattern: `["']([A-Za-z0-9_.+=|?#~@!$%^&*-]{20,512})["']`
2. Reject: all-lowercase underscore identifiers, dotted namespace constants, OID values,
   JS strict-equality fragments, URL query strings, HTTP header name patterns
3. Compute Shannon entropy — reject if below `entropyThreshold` (default: 3.5 bits/char)
4. Reject: no digits and no strong symbols (pure CSS class names)
5. Require: `ENTROPY_CONTEXT_KW` keyword in ±80-char window **outside** the value span
   OR `isSemanticSecretKey()` on the recovered key name from the same line

**Context keywords (examples):** `api_key`, `apikey`, `client_secret`, `access_token`,
`subscription_key`, `apim_key`, `bearer_token`, `aws_secret`, `ssh_key`, `password`,
`encryption_key`, `cryptojs_key`, `encrypted_env`

---

### 8.6 Layer 6: SSR State Blob Scanner

**What:** Extracts and scans JSON configuration objects injected by server-side
rendering frameworks (Next.js, Nuxt, Redux, SvelteKit).

**Runs at:** FULL

**Patterns matched:**
- `window.__NEXT_DATA__ = {...}`
- `window.__REDUX_STATE__ = {...}`
- `window.__INITIAL_STATE__ = {...}` / `__PRELOADED_STATE__` / `__NUXT__` / `__APP_STATE__`
- `window.__CONFIG__ = {...}` / `window._env_ = {...}` / `window.appConfig = {...}` / `window.serverData = {...}`
- `<script type="application/json">...</script>` (Next.js `__NEXT_DATA__` and SvelteKit)

Each matched blob is passed to `walkJsonBody()` for recursive JSON scanning.

---

### 8.7 Layer 7: Getter Function Scanner

**What:** Catches secrets that are returned from function expressions in JavaScript,
rather than assigned as bare string literals — invisible to the KV and anchored scanners.

**Runs at:** FULL, JS content only

**Patterns:**
- `GETTER_ARROW_SHORT`: `const getApiKey = () => 'VALUE'`
- `GETTER_FUNC_RETURN`: `const getApiKey = function() { return 'VALUE'; }`

**Gate:** semantic key name in the variable name OR value is 60+ chars with high entropy

---

### 8.8 Layer 8: JSON Deep Walker

**What:** Uses Gson to parse a JSON body and walk every key/value leaf to depth 20.
Applies the full semantic + entropy + placeholder gates at each leaf. Capped at 50
findings per body to prevent noise on large API responses.

**Runs at:** FULL, JSON Content-Type

**Special behavior in `checkJsonLeaf()`:**
- OAuth token fast-path: `access_token`, `refresh_token`, `id_token` keys → **always HIGH CERTAIN**, no entropy gate
- Bare `"token"` or `"secret"` keys: allowed with high entropy (catches common API response field names)
- Azure GUID bypass: UUID values pass for `isAzureCredentialKey()` key names

---

### 8.9 Layer 9: XML Leaf Scanner

**What:** Extracts `<tagName>value</tagName>` text content from XML API responses
and passes each through the same `checkJsonLeaf()` gates as the JSON walker.

**Runs at:** FULL, XML Content-Type

---

### 8.10 Layer 10: URL Credentials

**What:** Detects credentials embedded in URL userinfo (`user:pass@host`) or
as password query parameters (`?password=X`).

**Runs at:** ALL tiers

**Patterns:**
- `URL_WITH_CREDS`: `https://user:pass@host` (basic-auth style)
- `URL_QUERY_CREDS`: `https://host/path?password=X` (query-parameter style)

---

### 8.11 Layer 11: PII Detection

**What:** Detects Personally Identifiable Information that should never appear in
HTTP responses.

**Runs at:** FULL, when PII setting enabled

| Type | Rule ID | Detection Method |
|---|---|---|
| SSN | SSN_PII | Format regex `\b{3}-{2}-{4}\b` + context keyword in ±3 lines (`ssn`, `social_security_number`, `tin`, `itin`, etc.) |
| Credit Card | CC_PII | Format regex for Visa/MC/Amex/Discover + **Luhn algorithm validation** + numeric context guards |

The **Luhn check** eliminates ~90% of CC false positives (sequential numbers, IDs, timestamps
that match the digit pattern but fail the checksum).

---

### 8.12 Layer 12: Request Header Scanning

**What:** Scans credential-carrying request headers (not just response bodies).

**How:**
- Pass 1 (named check): flags `KNOWN_SECRET_HEADERS` (e.g. `x-api-key`, `ocp-apim-subscription-key`,
  `authorization`, `app_key`, `x-amz-security-token`) + `isSemanticSecretKey()` matches
- Pass 2 (blob scan): runs anchored vendor patterns on the full concatenated header blob
- At FULL tier: also runs high-entropy scanner on headers blob
- Request body: anchored tokens + URL creds; at LIGHT+ adds DB strings; at FULL adds KV + entropy + JSON walk

**Suppressions on requests:**
- JWTs (every authenticated request carries one — not a finding)
- Opaque Bearer tokens with no known vendor prefix (dynamic session/OAuth tokens — per-request noise)
- Cross-request deduplication: same value seen in a previous request in this session is skipped

---

## 9. Key Classification Engine

### 9.1 `isSemanticSecretKey(name)`

The most important gate in the entire scanner. Determines whether a key name
is semantically a credential holder.

**Decision tree:**
1. Reject keys ending in `_endpoint`, `_url`, `_uri`, `_host` (always URLs, never secrets)
2. Allow `data-api-key`, `data-auth-token` — reject other `data-*` attributes
3. Directly allow single-word keys: `password`, `passwd`, `pass`, `pwd`, `secret`
4. Match against `REAL_SECRET_KEYNAME` regex (high-precision compound patterns like `api_key`,
   `access_token`, `client_secret`, `ocp_apim_subscription_key`, etc.)
5. CamelCase + underscore split into segments → require:
   - At least one segment in `SECRET_KEY_PREFIXES`: `api`, `app`, `auth`, `access`, `secret`,
     `private`, `signing`, `master`, `resource`, `storage`, `subscription`, `client`, `service`,
     `account`, `application`, `apim`, `ocp`, `bearer`, `payment`, `jwt`, `session`, `refresh`,
     `x`, `consumer`, `encrypt`, `decrypt`, `ssh`, `admin`, `db`, `database`, `root`, `slack`, `user`
   - At least one segment that is a secret-component word: `key`, `token`, `secret`,
     `subscription`, `credential`, `password`, `passwd`, `pwd`, `pass`, `auth`, `id`
6. Reject Angular/webpack module manifest keys (last two segments are `module_ts`, `component_js`, etc.)
7. Reject UI display-label keys (last segment is `label`, `hint`, `placeholder`)

### 9.2 `isForcedNoiseKey(key)`

Exact-match (case-insensitive) against a 90+ entry set of known noise key names.
Hard rejects regardless of value. Covers:

- Generic bare names: `key`, `value`, `name`, `id`, `code`, `flag`, `type`, `format`, `scope`, `tag`
- OAuth/OIDC flow params: `redirect_uri`, `client_id`, `tenant_id`, `csrf`, `csrftoken`, `nonce`
- OIDC discovery doc fields: `issuer`, `token_endpoint`, `authorization_endpoint`, `jwks_uri`
- MSAL/ADAL library constants: `interaction_status_key`, `acquire_token_start`, `adal_id_token`
- Firebase config: `authdomain`, `projectid`, `storagebucket`, `messagingsenderid`, `databaseurl`
- App Insights SDK constants: `sdkextension`, `sdkversion`, `instrumentationkey`
- Session identifiers: `sessionid`, `jsessionid`, `phpsessid`
- UI state keys: `alertkey`, `cachekey`, `sortkey`, `tabkey`, `panelkey`, `rowkey`, `menukey`
- OAuth2 params: `resource`, `resource_id`, `resourceid`
- Org identifiers: `orgid`, `org_id`

### 9.3 `NOISE_KEYNAMES` Regex

Regex full-match against key names for pattern-based noise rejection:

- Exact UI keys: `class`, `classname`, `tooltip`, `placeholder`, `label`, `title`, `description`, `message`, `text`, `subject`, etc.
- Suffix-based: keys ending in `msg`, `errormsg`, `regex`, `pattern`, `policy`, `caption`, `hint`, `domain`, `url`, `uri`, `host`, `path`, `endpoint`, `baseurl`, `homepage`, `website`
- State/type discriminators: keys ending in `type`, `error`, `state`, `kind`
- Angular/webpack module manifest keys: `..._module_ts`, `..._component_js`, etc.

---

## 10. False Positive Reduction Summary

| Mechanism | What It Blocks |
|---|---|
| `FORCED_NOISE_KEYS` (90+ entries) | Bare field names, OAuth params, OIDC discovery, Firebase config, session IDs |
| `NOISE_KEYNAMES` regex | UI/layout keys, URL/endpoint keys, type-discriminator keys |
| `isSemanticSecretKey` compound check | Requires recognized domain prefix + target word pairing |
| `REAL_SECRET_KEYNAME` regex | Precision-anchored pattern for well-known compound key names |
| `isPlaceholder(val)` | Rejects values like `YOUR_API_KEY`, `<secret>`, `EXAMPLE`, `xxxx`, `changeme` |
| JWT suppression | Skips JWT values in KV/entropy scanners (session tokens, not hardcoded secrets) |
| Opaque Bearer suppression | Suppresses `Authorization: Bearer X` without known vendor prefix from request findings |
| CDN blocklist (25+ domains) | Skips responses from analytics/CDN hosts (jsDelivr, Segment, Hotjar, DoubleClick, etc.) |
| `isProbableSecretValue(val)` | Rejects pure-alpha strings, values ≤ 7 chars, common English words |
| GUID gate | UUID values only reported when key explicitly names an Azure credential |
| Blockchain hash guard | Rejects `txid`, `txhash`, `wallet`, `eth` key names |
| Template expression filter | Rejects `$event`, `{{ expr }}`, `${var}` Angular/Vue runtime values |
| Framework attribute filter | Rejects `ng-*`, `v-*`, `x-on:*`, `@click`, `:class` directive keys |
| Luhn validation (CC) | Eliminates ~90% of credit card false positives |
| SSN context guard | SSN format requires keyword (`ssn`, `social_security_number`, etc.) in ±3 lines |
| Entropy threshold (default 3.5) | Entropy scanner rejects low-entropy values (common words, sequential strings) |
| Angular/webpack module key check | In-line reject in both `scanGenericKV` and `checkJsonLeaf` for module path keys |
| `extractNearbyKeyName` | Entropy scanner recovers key from same line; if key is a noise key, skip |
| JWT issuance detection | Request has credential headers → JWT in response → upgrade to HIGH (not suppress) |
| Bearer JWT in request → suppress response JWT | Authenticated endpoint → don't report every JWT in every response |

---

## 11. Severity Model

| Level | Meaning | Example |
|---|---|---|
| **HIGH** | Confirmed active credential — rotate immediately | GitHub PAT, Stripe live key, AWS access key, PEM private key, DB password |
| **MEDIUM** | Token confirming a live service integration | Twilio SID, Google API key, Mailchimp, SSN |
| **LOW** | Identifier or key with limited standalone risk | Algolia App ID, Azure APIM Client ID, Azure App Insights iKey |
| **INFORMATION** | Structural finding, schema-level signal | GCP service account JSON structure, GUID token identifier |

---

## 12. Confidence Model

| Level | What It Means |
|---|---|
| **CERTAIN** | Fixed-format anchored match — the value can only be a specific vendor's token |
| **FIRM** | Semantic key + probable value, but could theoretically be a false positive |

---

## 13. Rule ID Taxonomy

Rule IDs follow a `VENDOR_TYPE_NNN` pattern:

| Prefix | Category |
|---|---|
| `GITHUB_PAT_*` | GitHub personal access tokens |
| `GITLAB_PAT_*` | GitLab tokens |
| `AWS_KEY_*` | AWS credentials |
| `AZURE_*` | All Azure / Microsoft cloud |
| `GCP_KEY_*` | Google Cloud Platform |
| `TWILIO_*` | Twilio SIDs and auth tokens |
| `STRIPE_*` | Stripe keys |
| `SLACK_*` | Slack tokens and webhooks |
| `OPENAI_*` | OpenAI API keys |
| `DB_CONN*` | Database connection strings |
| `URL_CREDS*` | Embedded URL credentials |
| `GENERIC_KV` | Generic key-value scanner hit |
| `ENTROPY_TOKEN` | High-entropy scanner hit |
| `JSON_WALK` | JSON deep-walker hit (includes OAuth fast-path) |
| `GETTER_FUNC` | JS getter function scanner hit |
| `REQ_HEADER` | Secret found in request header |
| `SSN_PII` | Social Security Number |
| `CC_PII` | Credit card number |
| `JWT_TOKEN_001` | JWT token (context-dependent severity) |
| `CRYPTOJS_*` | CryptoJS keys and encrypted blobs |

---

## 14. Reporting

### HTML Report (all-in-one)
- Single self-contained HTML file with embedded CSS/JS
- Findings table with severity, rule, key name, masked value, source URL, context snippet
- Domain filter dropdown (dynamically populated from findings)
- Severity badge coloring (red/orange/yellow/blue)
- Clickable source URLs (opens in browser)

### Per-Domain ZIP
- One HTML report file per unique hostname
- Grouped by `targetUrl` host (the user-entered scan target)
- Fallback to `sourceUrl` host if no target URL set
- Hostname extraction handles bare hostnames (auto-prepends `https://` for parsing)

### CSV Export
- Raw findings as flat CSV: ruleId, ruleName, keyName, value, severity, confidence, URL

---

## 15. Settings

| Setting | Default | Effect |
|---|---|---|
| Scan tier | FULL | Controls which scan phases run |
| Entropy threshold | 3.5 bits/char | Minimum Shannon entropy for high-entropy scanner |
| PII detection | Enabled | Toggle SSN and credit card scanning |
| Scan request headers/body | Enabled | Toggle scanning of outbound request credentials |
| Allow insecure SSL | Disabled | Whether to accept invalid TLS certs in bulk scan |
| Custom rules enabled | Enabled | Toggle user-defined regex rules |
| CDN blocklist | 25+ pre-populated | Newline-separated hostnames to skip entirely |
| Key name blocklist | 3 pre-populated | Substring patterns — matching key names suppressed |
| Key name allowlist | Empty | Substring patterns — matching keys always reported |
| Custom rules | Empty | User-defined rules: `RuleName \| regex \| severity` |

---

## 16. Bulk Scan Tab Specifics

- **URL input:** Paste/import `.txt`, `.csv`, or `.har` files (HAR import = scan without live fetch)
- **Concurrency:** 1–50 threads (default 25), configurable per scan
- **Script-src following:** Fetches and scans `<script src>` URLs found in HTML responses
- **Webpack chunk following:** Follows `.chunk.js` / `.bundle.js` references in JS bundles (depth 1)
- **Scope Monitor:** Captures passive proxy findings for watched hosts into the Bulk Scan table
- **Headless Browse:** Launches Chrome/Chromium through Burp proxy to capture XHR/Fetch calls from SPAs
- **Scan Site Map:** Sweeps all JS/HTML already captured in Burp's Target site map
- **Deduplication:** `seenFindings` set per scan run prevents duplicate rows in the table

---

## 17. Thread Safety Model

- `SecretScanner` is **fully stateless** in all scan paths — safe for concurrent calls
- `ScanSettings` uses `volatile` fields for all primitives; `synchronized` methods for list operations
- `seenRequestValues` (cross-request dedup set) uses `Collections.synchronizedSet()`
- `currentTargetUrl` and `hostToTargetUrl` in `BulkScanPanel` use `ThreadLocal` and a `ConcurrentHashMap`
- `BulkScanPanel.appendFinding()` synchronizes on a `seenFindings` `LinkedHashSet` for table dedup
