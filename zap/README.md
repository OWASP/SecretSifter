# OWASP SecretSifter — ZAP Add-on

Passive detection of secrets, credentials, API tokens and PII exposed in live
HTTP traffic — response bodies, JavaScript bundles, server-side-rendered state
blobs (Next.js / Nuxt / Redux), JSON/XML responses, and request headers.

Part of the [OWASP SecretSifter](https://owasp.org/projects/secretsifter)
project. This add-on runs the unified SecretSifter detection engine — **437
rules** (158 format-anchored vendor token patterns + 279 context rules, loaded
from YAML rule packs) plus generic key/value, connection-string, JWT,
high-entropy and PII detectors — shared with the SecretSifter Burp, desktop and
browser editions. ZAP-specific code is a single `PluginPassiveScanner` adapter
that feeds HTTP messages to the engine and maps findings onto ZAP alerts.

All scanning is local to ZAP. The add-on makes no outgoing network connections
of its own.

## Build

```bash
./gradlew build
# → build/zapAddOn/bin/zap-secretsifter-alpha-1.0.0.zap
```

## Install (local)

ZAP → File → Load Add-on file… → select the `.zap` produced above. Exposed
secrets appear under the **Alerts** tab as `Exposed Secret: <type>` passive-scan
findings, with the matched evidence, source URL, and a risk level based on the
secret type.

## Detection scope

Passive only. The add-on inspects traffic already proxied through ZAP; it does
not actively probe for files/paths. Coverage centres on secrets that appear in
browser-facing traffic (client-side keys, tokens in bundles and API responses,
credentials in headers).

## License

MIT — see [LICENSE](LICENSE).

## Project

OWASP SecretSifter: <https://owasp.org/projects/secretsifter>
Source (all editions): <https://github.com/OWASP/SecretSifter>
