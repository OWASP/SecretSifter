# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/1.0.0/).

## [Unreleased]

## [1.0.0] - Alpha
### Added
- Passive scan rule that detects secrets, credentials, API tokens and PII
  exposed in live HTTP traffic: response bodies, JavaScript bundles, SSR state
  blobs (Next.js / Nuxt / Redux), and request headers/bodies.
- Unified 437-rule detection engine (158 format-anchored vendor tokens + 279
  context rules, loaded from YAML rule packs) plus generic key/value,
  connection-string, JWT, SSR-state, and PII detectors — shared verbatim with
  the OWASP SecretSifter Burp, desktop and browser editions.
- False-positive suppression gates (placeholder detection, entropy gating,
  public-key/CDN allowlisting) carried over from the Burp edition.
