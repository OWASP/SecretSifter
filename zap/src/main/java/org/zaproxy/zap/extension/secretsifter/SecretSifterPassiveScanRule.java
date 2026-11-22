/*
 * SecretSifter — ZAP passive scan rule
 *
 * Detects secrets, credentials, API tokens and PII exposed in live HTTP traffic
 * (response bodies, JS bundles, SSR state blobs, request headers/bodies).
 *
 * The detection engine (com.secretscanner.SecretScanner + Patterns) is shared
 * verbatim with the Burp edition; this class is only the ZAP adapter that feeds
 * it HTTP messages and maps findings onto ZAP Alerts.
 */
package org.zaproxy.zap.extension.secretsifter;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import com.secretscanner.ScanSettings;
import com.secretscanner.SecretFinding;
import com.secretscanner.SecretScanner;

public class SecretSifterPassiveScanRule extends PluginPassiveScanner {

    /** Unique plugin id for this add-on's passive rule (third-party high range). */
    private static final int PLUGIN_ID = 110020;

    private static final Logger LOGGER = LogManager.getLogger(SecretSifterPassiveScanRule.class);

    // Shared settings + stateless engine. scanText() holds no per-request state.
    private static final ScanSettings SETTINGS = new ScanSettings();
    private static final SecretScanner ENGINE =
            new SecretScanner(SETTINGS, new com.secretscanner.Logging());

    /** Exposed so a future options panel can mutate detection behaviour. */
    public static ScanSettings settings() {
        return SETTINGS;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!SETTINGS.isEnabled()) {
            return;
        }
        try {
            String url = msg.getRequestHeader().getURI().toString();
            List<SecretFinding> findings = new ArrayList<>();

            // --- Response body ---
            if (msg.getResponseBody() != null && msg.getResponseBody().length() > 0) {
                String ct = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
                String body = msg.getResponseBody().toString();
                findings.addAll(ENGINE.scanText(body, ct, url));
            }

            // --- Request headers + body (opt-in; on by default) ---
            if (SETTINGS.isScanRequestsEnabled()) {
                StringBuilder hdrBlob = new StringBuilder();
                for (HttpHeaderField h : msg.getRequestHeader().getHeaders()) {
                    hdrBlob.append(h.getName()).append(": ").append(h.getValue()).append('\n');
                }
                if (hdrBlob.length() > 0) {
                    // The core recognises the "[REQ-HEADERS]" marker and applies the
                    // named-credential-header logic used by the Burp proxy path.
                    findings.addAll(ENGINE.scanText(hdrBlob.toString(), null,
                            url + " [REQ-HEADERS]"));
                }
                if (msg.getRequestBody() != null && msg.getRequestBody().length() > 20) {
                    String reqCt = msg.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE);
                    findings.addAll(ENGINE.scanText(msg.getRequestBody().toString(),
                            reqCt, url + " [req]"));
                }
            }

            // --- Raise one alert per unique (rule, value) ---
            Set<String> seen = new HashSet<>();
            for (SecretFinding fnd : findings) {
                String dedupe = fnd.ruleId() + '|' + fnd.matchedValue();
                if (!seen.add(dedupe)) {
                    continue;
                }
                raiseAlertFor(fnd, msg);
            }
        } catch (Exception e) {
            LOGGER.warn("SecretSifter passive scan failed: {}", e.toString());
        }
    }

    private void raiseAlertFor(SecretFinding f, HttpMessage msg) {
        String displayValue = f.matchedValue().length() > 80
                ? f.matchedValue().substring(0, 77) + "..."
                : f.matchedValue();

        String description =
                "SecretSifter detected a secret, credential, API token or sensitive value "
                        + "exposed in HTTP traffic (" + f.ruleName() + "). "
                        + "Secrets exposed in JavaScript, API responses or HTML source can be "
                        + "harvested by anyone with access to the application.";

        String solution =
                "Remove the secret from client-accessible content. Use server-side environment "
                        + "variables and never embed live credentials in front-end assets or API "
                        + "responses. Rotate or revoke the identified credential immediately.";

        String otherInfo =
                "Rule: " + f.ruleName() + " (" + f.ruleId() + ")\n"
                        + "Key / field: " + f.keyName() + "\n"
                        + "Matched value: " + displayValue + "\n"
                        + "Source: " + f.sourceUrl();

        newAlert()
                .setName("Exposed Secret: " + f.ruleName())
                .setRisk(riskOf(f.severity()))
                .setConfidence(confidenceOf(f.confidence()))
                .setDescription(description)
                .setOtherInfo(otherInfo)
                .setSolution(solution)
                .setReference("https://github.com/secretsifter")
                .setEvidence(f.matchedValue())
                .setCweId(200) // Exposure of Sensitive Information to an Unauthorized Actor
                .setWascId(13) // Information Leakage
                .setMessage(msg)
                .raise();
    }

    private static int riskOf(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase()) {
            case "CRITICAL", "HIGH" -> Alert.RISK_HIGH;
            case "MEDIUM" -> Alert.RISK_MEDIUM;
            case "LOW" -> Alert.RISK_LOW;
            default -> Alert.RISK_INFO;
        };
    }

    private static int confidenceOf(String confidence) {
        return switch (confidence == null ? "" : confidence.toUpperCase()) {
            case "CERTAIN" -> Alert.CONFIDENCE_HIGH;
            case "FIRM" -> Alert.CONFIDENCE_MEDIUM;
            default -> Alert.CONFIDENCE_LOW;
        };
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return "OWASP SecretSifter — Exposed Secrets & Credentials";
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(
                newAlert()
                        .setName("Exposed Secret: AWS Access Key")
                        .setRisk(Alert.RISK_HIGH)
                        .setConfidence(Alert.CONFIDENCE_HIGH)
                        .setDescription("Example: an AWS access key id exposed in a JS bundle.")
                        .setEvidence("AKIAIOSFODNN7EXAMPLE")
                        .setCweId(200)
                        .setWascId(13)
                        .build());
        return alerts;
    }
}
