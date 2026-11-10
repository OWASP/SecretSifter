# OWASP SecretSifter — Desktop

A standalone desktop application (macOS and Windows) that finds exposed credentials,
API keys, tokens, and other secrets in live web traffic, JavaScript bundles, API
responses, and HAR archives.

Unlike the Burp extensions in this repository, the desktop edition is fully
self-contained — it ships its own HTTPS man-in-the-middle proxy, a headless-browser
crawler (Playwright), and an MCP server — so it runs without Burp Suite.

## Features

- **437 built-in detection rules** (158 format-anchored + 279 context-gated) covering
  AWS, GitHub, GitLab, Stripe, Twilio, SendGrid, Google, Slack, Azure, and 200+ more
  services — the same unified engine as the Burp MCP edition (`../burp-mcp`).
- **Live key validation** (opt-in): offline checks (JWT expiry, Luhn) run with no
  network calls; live provider checks confirm whether a detected key is still active.
- **Built-in HTTPS proxy** with on-the-fly per-host certificate generation.
- **Headless-browser crawling** for single-page apps (Playwright / Edge).
- **MCP server** (`secretsifter-desktop`) exposing the scanner to AI assistants.
- **HTML / CSV / JSON reports**.

## Build

Requires JDK 17+ and Gradle.

```bash
cd desktop
gradle packageInstaller      # builds the native installer (DMG on macOS, EXE on Windows)
gradle shadowJar             # or just the runnable fat JAR
```

The installer is written to `build/installer/`.

## Download

Prebuilt installers are attached to this repository's
[Releases](https://github.com/OWASP/SecretSifter/releases) (tag `desktop-v1.8.0`).

## License

MIT — see the [LICENSE](../LICENSE) at the repository root.

Part of the [OWASP SecretSifter](https://owasp.org/www-project-secretsifter/) project.
