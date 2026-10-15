# OWASP SecretSifter

SecretSifter is an OWASP Incubator project that finds credentials exposed in what web applications actually deliver to the browser: JavaScript bundles, configuration responses and other live content.

Pre-deployment secret scanning looks at source code. Some credentials are only introduced at build time or runtime, so they never appear in the repository being scanned. SecretSifter inspects traffic as it reaches the browser and reports each finding with its location and evidence for a tester to assess.

## Editions

| Edition | Get it | Source |
|---|---|---|
| Burp Suite extension | Build from source | [`burp-extension/`](burp-extension) (MIT) |
| Burp Suite extension with AI triage and MCP | Build from source | [`burp-mcp/`](burp-mcp) (MIT) |
| Chrome extension | [Chrome Web Store](https://chromewebstore.google.com/detail/secretsifter-live-credent/okjoofmgkkgopigaipccailblmpcchjo) | Coming soon (MIT, on the roadmap) |
| Firefox extension | [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/secretsifter-extension/) | Coming soon (MIT, on the roadmap) |
| Desktop app (macOS, Windows) | [Releases](https://github.com/secretsifter/secretsifter-desktop) | Coming soon (MIT, on the roadmap) |
| InsecureShield practice target (synthetic credentials only) | [secretsifter/insecureshield-demo](https://github.com/secretsifter/insecureshield-demo) | MIT |

Both Burp editions build with `./gradlew shadowJar` (Java 17+). Each folder has its own README with build and install steps.

## Research

- H. Gorijala, "Secrets That Survive Everything: Runtime Credential Exposure in Production Web Applications," *IEEE Access*, 2026. https://doi.org/10.1109/ACCESS.2026.3734984
- H. Gorijala, "SecretSifter: A Runtime Secret-Detection Engine for Live Web Traffic," *SoftwareX*, vol. 36, 103087, 2026. https://doi.org/10.1016/j.softx.2026.103087

## Responsible use

Only scan applications you own or are authorized to test. If you find a live credential, report it so it can be rotated, and never publish its value.

## Contributing

Issues and pull requests are welcome, especially new detection rules with test cases for both true and false positives.

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/). Sign off each commit with `git commit -s`.

## Project leaders

- Hemanth Gorijala ([hemanth.gorijala@owasp.org](mailto:hemanth.gorijala@owasp.org))

Project page: [owasp.org/projects/secretsifter](https://owasp.org/projects/secretsifter)

## License

Source code is licensed under MIT (see [LICENSE](LICENSE)). Documentation is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
