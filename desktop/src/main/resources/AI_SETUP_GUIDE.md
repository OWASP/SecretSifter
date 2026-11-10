# SecretSifter AI Scanner — Setup & Triage Guide

## Overview

SecretSifter exposes a Model Context Protocol (MCP) server that lets Claude (Desktop, CLI, VS Code)
drive the entire scanning workflow end-to-end through natural language:

- Start scans against single targets, lists, or large target files in batches
- Monitor progress in real time
- Triage findings — update severity, delete false positives
- Export reports (CSV, JSON, HTML)
- Add and manage custom regex rules without touching the UI

---

## Prerequisites

| Item | Requirement |
|---|---|
| SecretSifter | v1.1.0+ (built from source with AI changes) |
| Claude Desktop | Latest version from claude.ai/download |
| Claude Code CLI | v2.1+ — run `claude --version` to verify |
| Node.js | v18+ — required by Claude Code CLI |
| Git Bash | Required by Claude Code on Windows (`C:\Users\<you>\Git\bin\bash.exe`) |

---

## Step 1 — Build and install SecretSifter

Open a terminal in the project folder and run the build script:

```bat
cd C:\Users\hegori\Downloads\secretsifter-windows\secretsifter-windows
build_obf.bat
```

When the build finishes, run the installer:

```
build\SecretSifter-1.1.0-windows-Setup.exe
```

> **Expected:** Installer completes and SecretSifter opens. If it does not open automatically,
> launch it from the Start menu or Desktop shortcut.

---

## Step 2 — Enable the MCP server in SecretSifter

1. Open SecretSifter
2. Click the **Settings** tab
3. Toggle **Enable MCP Server** → ON
4. Click **Apply**
5. Note the **Token** value shown — you will need it in Step 4

> **Expected:** Status label changes to `● Running on :7483`

---

## Step 3 — Verify Claude Code CLI is installed

In your VS Code terminal:

```
claude --version
```

> **Expected:** prints something like `Claude Code 2.1.114`

**If `claude` is not found:**

```powershell
# Add portable Node.js and Claude Code to PATH (adjust to your install location)
$env:PATH = "C:\Users\hegori\Downloads\nodejs\node-v22.13.1-win-x64;$env:PATH"
$env:PATH = "$env:APPDATA\npm;$env:PATH"
```

**If Git Bash error appears:**

```powershell
[System.Environment]::SetEnvironmentVariable(
    "CLAUDE_CODE_GIT_BASH_PATH",
    "C:\Users\hegori\Git\bin\bash.exe",
    "User"
)
# Close and reopen the terminal, then run claude again
```

---

## Step 4 — Connect Claude Code to SecretSifter

Run this once in your VS Code terminal. Replace `<TOKEN>` with the token from Step 2:

```
claude mcp add --transport sse secretsifter http://localhost:7483/sse --header "Authorization: Bearer <TOKEN>"
```

> **Expected output:** `Added MCP server "secretsifter"`

### Restart Claude Desktop (required)

Claude Desktop only reads MCP config at startup — it will not pick up the new server until restarted.

1. Right-click the Claude Desktop icon in the system tray → **Quit**
2. Reopen Claude Desktop from the Start menu
3. Wait for it to fully load before continuing

### If using Claude Code CLI in the terminal

Close the current terminal session and reopen it:

```
exit
```

Open a new terminal and run `claude` again.

### Verify the connection

```
/mcp
```

> **Expected output:**
> ```
> secretsifter
>   Status: connected
>   Tools: 26
> ```

> If the output shows **No MCP servers configured** or **failed** — go to the Triage section below.

---

## Step 5 — Add custom regex rules (optional)

Custom rules let you define your own token patterns on top of the 150+ built-in vendor rules.

**Format:** `RuleName | regex | severity`

Severity must be one of: `HIGH`, `MEDIUM`, `LOW`, `INFORMATION`

Lines starting with `#` are treated as comments and ignored.

### Via the SecretSifter UI

1. Open SecretSifter → **Settings** tab
2. Find the **Custom Regex Rules** section
3. Add your rules, one per line:

```
# Messaging
TelegramBotToken | \b[0-9]{5,16}:A[0-9A-Za-z_-]{34}\b | HIGH
DiscordBotToken  | \bMT[A-Za-z0-9]{22}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b | HIGH

# AI / ML platforms
HuggingFaceToken | \bhf_[A-Za-z0-9]{34}\b | HIGH
ReplicateToken   | \br8_[A-Za-z0-9]{38}\b | HIGH

# Project management
LinearApiKey     | \blin_api_[A-Za-z0-9]{40}\b | HIGH
NotionToken      | \bsecret_[A-Za-z0-9]{43}\b | HIGH
```

4. Toggle **Enable custom rules** → ON
5. Click **Save Settings**

### Via the Claude terminal

```
set_custom_rules rules="TelegramBotToken | \b[0-9]{5,16}:A[0-9A-Za-z_-]{34}\b | HIGH
HuggingFaceToken | \bhf_[A-Za-z0-9]{34}\b | HIGH"
```

### Import from a file

In the Settings UI click **Import .txt** and select a text file with one rule per line.
You can also export your current rules to a file with **Export .txt**.

---

## Step 6 — Run scans from Claude

Open Claude Desktop or a Claude Code CLI terminal and type naturally.

### Single target

> Scan https://example.com and show me all HIGH findings

### Multiple targets

> Scan these URLs: https://app1.com, https://app2.com — use 15 threads

### Targets file — first batch

> Load targets from C:\pentest\targets.txt and scan the first 15 targets

### Targets file — next batch

> Scan the next 15 targets from C:\pentest\targets.txt starting at line 15

### Preview a targets file before scanning

> Show me lines 0–20 from C:\pentest\targets.txt

### Monitor progress

> What is the current scan status?

### Triage findings

> Show all HIGH and MEDIUM findings  
> Delete findings at index 3 and 7 — they are false positives  
> Change finding at index 5 to LOW severity  

### Export report

> Export the report as HTML to my Desktop  
> Export findings as CSV

### Manage custom rules

> Show me the current custom rules  
> Add a rule for Grafana tokens: GrafanaToken | \bglsa_[A-Za-z0-9]{32}\b | HIGH

### Manage CDN blocklist and key filters

> Show me the CDN blocklist  
> Add cloudflare.com to the CDN blocklist  
> Show key blocklist and allowlist  
> Add api_key to the key allowlist so it always gets reported

### View logs and HAR scans

> Show me the last 50 ERROR log lines  
> Scan the HAR file at C:\Users\me\capture.har  

### View built-in detection rules

> List all built-in pattern rules

### Bulk triage

> Delete all INFORMATION severity findings

---

## Quick Reference — All 26 MCP Tools

| Tool | Description |
|---|---|
| `start_scan` | Start a scan — accepts `urls`, `targets_file`, `batch_start`, `batch_size`, `threads`, `browser_mode`, `follow_scripts`, `follow_chunks` |
| `stop_scan` | Stop the running scan immediately |
| `pause_scan` | Pause the scan (browser mode only) |
| `resume_scan` | Resume a paused scan |
| `get_scan_status` | Returns running state, URLs done, findings count |
| `get_target_status` | Per-target outcome: ✅ OK, ❌ Unreachable, 🔒 Auth required, ⏱ Timed out. Optional `filter`: ok / failed / auth / timeout |
| `get_findings` | All findings; filter by `severity` or `target_url`; each finding has an `index` |
| `get_summary` | Finding count grouped by severity |
| `update_finding` | Change `severity` or `confidence` of a finding by `index` |
| `delete_finding` | Delete one finding (`index`) or multiple (`indices` array) — false positive removal |
| `bulk_delete_findings` | Delete all findings matching `severity`, `confidence`, or `rule_id` in one call |
| `clear_findings` | Remove all findings from the session |
| `export_report` | Export to `csv`, `json`, or `html`; optional `output_path` |
| `get_custom_rules` | Show current custom regex rules and enabled state |
| `set_custom_rules` | Replace all custom rules (`rules` text + optional `enabled` flag) |
| `list_builtin_patterns` | List all built-in rule IDs, names, and severities |
| `get_settings` | Read all current scan settings (tier, entropy, PII, timeout, browser, key filters, CDN count) |
| `set_settings` | Update `tier`, `entropy_threshold`, `pii_enabled`, `scan_requests`, `browser_enabled`, `browser_max_pages`, `browser_path`, `url_timeout_seconds`, `custom_rules_enabled` |
| `get_cdn_blocklist` | Get the CDN / third-party domain blocklist entries |
| `set_cdn_blocklist` | Replace the CDN blocklist with a newline-separated list of hostname substrings |
| `get_key_filters` | Get the key name blocklist and allowlist |
| `set_key_filters` | Update key name `key_blocklist` and/or `key_allowlist` |
| `get_logs` | Read the application log; optional `filter` (ERROR/INFO) and `limit` |
| `clear_logs` | Clear the application log buffer |
| `scan_har_file` | Scan a HAR file for secrets (async); use `get_findings` and `get_logs` to monitor |
| `preview_targets_file` | Preview URL batches from a file without starting a scan |

---

## Triage — When Things Go Wrong

### `/mcp` shows "No MCP servers configured"

**Cause A — MCP entry was never added**

Run the add command and restart:

```
claude mcp add --transport sse secretsifter http://localhost:7483/sse --header "Authorization: Bearer <TOKEN>"
```

Then restart Claude Desktop (quit from system tray → reopen) or close and reopen the terminal session.

**Cause B — Config file is in the wrong location**

Check which file Claude Code is reading:

```
claude --mcp-debug
```

Then verify the config manually:

```powershell
cat "$env:USERPROFILE\.claude\settings.json"
```

The secretsifter entry must look exactly like this:

```json
"secretsifter": {
  "type": "sse",
  "url": "http://localhost:7483/sse",
  "headers": {
    "Authorization": "Bearer <TOKEN>"
  }
}
```

**Cause C — Missing `"type": "sse"` field**

The `claude mcp add` command adds this automatically. If you edited the file manually and omitted it, add `"type": "sse"` to the entry then restart Claude.

**Cause D — SecretSifter MCP server is not running**

Open SecretSifter → Settings → check the status shows `● Running on :7483`.
If it shows `○ Stopped`, toggle Enable MCP Server → ON → Apply.

---

### "I copied the config / saved settings but Claude still can't connect"

This is the most common setup pitfall. The config tells Claude **where** the server is — but the
server itself must be running first. The config can be saved at any time; the server only runs when
explicitly enabled.

**Step-by-step self-diagnosis:**

**1. Check the MCP server status inside SecretSifter**

Open SecretSifter → **Settings** tab → look at the status label next to the MCP server section.

| Label | Meaning | Action needed |
|---|---|---|
| `● Running on :7483` | Server is up — config is correct | None — restart Claude and test |
| `○ Stopped` | Server was never started / was disabled | Toggle **Enable MCP Server** → ON → click **Apply MCP Settings** |
| `✗ Failed: …` | Server tried to start but hit an error (usually port conflict) | See Step 3 below |

**2. Confirm the port is actually listening**

Open PowerShell and run:

```powershell
netstat -ano | findstr :7483
```

> **Expected when running:**
> ```
>   TCP    0.0.0.0:7483    0.0.0.0:0    LISTENING    <PID>
> ```
> If there is no output at all — the server is not running. Go back to Step 1 and enable it.

**3. If the port is blocked by another process**

Find the PID from the `netstat` output above, then:

```powershell
# Replace 1234 with the actual PID from netstat
Get-Process -Id 1234 | Select-Object Id, Name, Path
```

If it is a leftover SecretSifter process: kill it and relaunch SecretSifter.
If it is something else: change the MCP port in SecretSifter → Settings → enter a free port
(e.g. 7484) → Apply → then re-add the MCP server in Claude with the new port:

```
claude mcp remove secretsifter
claude mcp add --transport sse secretsifter http://localhost:<NEW_PORT>/sse --header "Authorization: Bearer <TOKEN>"
```

**4. Verify the token in Claude's config matches SecretSifter**

The token SecretSifter uses is shown in the **Token** field in Settings.
Check what Claude has stored:

```powershell
# Claude Code CLI
cat "$env:USERPROFILE\.claude\settings.json" | Select-String "Bearer"

# Claude Desktop
cat "$env:APPDATA\Claude\claude_desktop_config.json" | Select-String "Bearer"
```

If the token differs (e.g. SecretSifter regenerated it after you last copied the config):

1. In SecretSifter → Settings → copy the token field value
2. Click **Copy Config** — this builds fresh JSON with the current port and token
3. Open the Claude config file and replace the old `Authorization` header value
4. Restart Claude Desktop or close/reopen the terminal

**5. Test the connection directly (without Claude)**

Open PowerShell and run a raw SSE request to confirm the server responds:

```powershell
$token = "YOUR_TOKEN_HERE"
$req = [System.Net.WebRequest]::Create("http://localhost:7483/sse")
$req.Headers.Add("Authorization", "Bearer $token")
$resp = $req.GetResponse()
$stream = $resp.GetResponseStream()
$reader = New-Object System.IO.StreamReader($stream)
$reader.ReadLine(); $reader.ReadLine()
$resp.Close()
```

> **Expected output** (two lines):
> ```
> event: endpoint
> data: /message?sessionId=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
> ```
> If you get a `401 Unauthorized` → token mismatch (Step 4).
> If you get a connection refused → server not running (Step 1).

**6. Restart Claude after fixing**

Claude Desktop and Claude Code CLI only read MCP config at startup.
After fixing the server or config, you must restart:

- **Claude Desktop** — right-click system tray icon → **Quit** → reopen from Start menu
- **Claude Code CLI** — type `exit` in the terminal → open a new terminal → run `claude`

Then verify with `/mcp` — status should show `connected` with 26 tools.

---

### `/mcp` shows `secretsifter` but status is `failed` or `disconnected`

**Check 1 — Port conflict**

```powershell
netstat -ano | findstr :7483
```

If another process is using port 7483, change the port in SecretSifter → Settings → Apply.
Then re-add the MCP server with the new port:

```
claude mcp remove secretsifter
claude mcp add --transport sse secretsifter http://localhost:<NEW_PORT>/sse --header "Authorization: Bearer <TOKEN>"
```

Restart Claude Desktop or the terminal session, then run `/mcp` again.

**Check 2 — Token mismatch**

Tokens must match exactly between SecretSifter and the Claude config.
Open SecretSifter → Settings → copy the token exactly as shown, then re-add:

```
claude mcp remove secretsifter
claude mcp add --transport sse secretsifter http://localhost:7483/sse --header "Authorization: Bearer <TOKEN>"
```

Restart Claude Desktop or terminal, then run `/mcp`.

**Check 3 — Restart both sides in order**

1. Close the Claude terminal session or quit Claude Desktop
2. In SecretSifter → Settings → toggle MCP off → Apply → toggle MCP on → Apply
3. Reopen Claude Desktop or terminal
4. Run `/mcp`

---

### Custom rules are not triggering

**Check 1 — Are the rules saved?**

In Claude terminal:

```
get_custom_rules
```

Should return your rules and `"enabled": true`. If empty, re-add via `set_custom_rules` or save in the UI.

**Check 2 — Is the format correct?**

Each line must be exactly: `RuleName | regex | severity`

Spaces around the pipe `|` are required. Severity must be `HIGH`, `MEDIUM`, `LOW`, or `INFORMATION` (case-insensitive, stored as upper).

**Check 3 — Is the regex valid?**

Invalid regex patterns are silently skipped. Test your regex at https://regex101.com (select Java flavour) before adding. Common issues:

- `\b` word boundary works correctly
- Character classes like `[A-Za-z0-9_-]` work correctly
- Quantifiers like `{34}` work correctly
- Do NOT double-escape in the UI text area — `\b` not `\\b`

**Check 4 — Is the matched value passing noise filters?**

Custom rules run through the same noise filters as built-in rules. Values that are:

- All digits (e.g. `123456`)
- All lowercase alpha (e.g. `example`)
- Pure hex under 24 characters
- Placeholder-like (`xxx`, `test`, `your_token_here`)
- SRI hashes (`sha256-…`)

...will be filtered out. If a real credential is being suppressed, add the key name to the
**Key Name Allowlist** in SecretSifter Settings and save.

---

### Scan completes but finds nothing

1. Check the scan tier: `get_settings` — if tier is `FAST`, only vendor tokens and URL credentials are checked. Use `set_settings tier=FULL` for the most thorough scan.
2. Check the CDN blocklist: Settings → CDN / Third-Party Blocklist — make sure the target domain is not accidentally listed there.
3. For JavaScript-heavy single-page apps, try browser mode: `start_scan urls="https://target.com" browser_mode=true`

---

### Full reset — clean slate

```
# 1. Remove the existing MCP server entry
claude mcp remove secretsifter

# 2. In SecretSifter: Settings → Regenerate token → Apply
#    Copy the new token from the Token field

# 3. Re-add with the new token
claude mcp add --transport sse secretsifter http://localhost:7483/sse --header "Authorization: Bearer <NEW_TOKEN>"

# 4. Restart Claude Desktop (quit from system tray → reopen)
#    OR close the terminal and reopen it

# 5. Verify
/mcp
```

---

## Notes

- SecretSifter must be running with MCP enabled **before** Claude tries to connect. Start SecretSifter first, then open Claude.
- Custom rules run on **all scan tiers** (FAST, LIGHT, FULL) — they are not tier-gated.
- The `index` in `get_findings` refers to the current position in the findings list. After deleting findings, indices shift — always call `get_findings` again before further triage operations.
- Bearer tokens used to authenticate to the MCP server are stored in `%APPDATA%\Roaming\Claude\claude_desktop_config.json` (Claude Desktop) or `%USERPROFILE%\.claude\settings.json` (Claude Code CLI). Keep these files private.
