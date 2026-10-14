package com.secretscanner;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.File;
import java.nio.file.Files;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Swing settings tab shown in Burp's suite-level tab bar.
 *
 * Controls:
 *   - Global enable/disable toggle
 *   - Entropy threshold spinner (0.0 – 6.0, step 0.1)
 *   - PII scanning enable/disable
 *   - CDN blocklist text area (one entry per line)
 *
 * Settings are persisted to Burp's preference store on Save.
 */
public class SettingsPanel {

    private static final String CUSTOM_RULES_PLACEHOLDER =
            "# Format: RuleName | regex | severity  (HIGH / MEDIUM / LOW / INFORMATION)\n" +
            "# Lines starting with # are comments and are ignored by the scanner.\n" +
            "#\n" +
            "# -- Examples (remove the leading # to activate) --\n" +
            "#\n" +
            "# InternalToken   | INT-[0-9]{8}-[A-Z]{4}                | HIGH\n" +
            "# InternalApiKey  | [a-zA-Z0-9]{32,45}                   | MEDIUM\n" +
            "# CorpJwtAudience | iss=corp-[a-z]+-service               | INFORMATION\n" +
            "# InternalHost    | [a-z]+-service\\.corp\\.internal       | LOW\n" +
            "# HardcodedPass   | password\\s*=\\s*[\"'][^\"']{8,}[\"']   | HIGH\n";

    private final ScanSettings settings;
    private final MontoyaApi   api;
    /** False in the BApp Store build — hides MCP section and excludes McpBridge usage entirely. */
    private final boolean      withMcp;

    // ---- Swing controls ----
    private JPanel       rootPanel;
    private ToggleSwitch enabledBox;
    private JSpinner     entropySpinner;
    private ToggleSwitch piiBox;
    private ToggleSwitch scanRequestsBox;
    private ToggleSwitch allowInsecureSslBox;
    private JTextArea    cdnArea;
    private JTextArea    keyBlocklistArea;
    private JTextArea    keyAllowlistArea;
    private JTextArea    customRulesArea;
    private ToggleSwitch customRulesEnabledBox;
    private ToggleSwitch customRulesOnlyBox;
    private JLabel       statusLabel;
    private ToggleSwitch mcpEnabledBox;
    private JLabel    mcpTokenLabel;
    private JTextArea mcpConfigArea;
    private McpBridge mcpBridge;   // set via setMcpBridge() after construction
    private JScrollPane settingsScrollPane;
    private JComboBox<String> aiProviderCombo;
    private JPasswordField    aiApiKeyField;
    private JTextField        aiEndpointField;
    private JTextField        aiModelField;
    private JPanel            aiKeyRow, aiEndpointRow, aiModelRow;

    /** Full build constructor — includes MCP server section. */
    public SettingsPanel(ScanSettings settings, MontoyaApi api) {
        this(settings, api, true);
    }

    /** Store build constructor — pass {@code false} to omit MCP server section. */
    SettingsPanel(ScanSettings settings, MontoyaApi api, boolean withMcp) {
        this.settings = settings;
        this.api      = api;
        this.withMcp  = withMcp;
        // Build UI on the Event Dispatch Thread
        if (SwingUtilities.isEventDispatchThread()) {
            buildUi();
        } else {
            try {
                SwingUtilities.invokeAndWait(this::buildUi);
            } catch (Exception e) {
                SwingUtilities.invokeLater(this::buildUi);
            }
        }
    }

    /** Returns the Swing panel to register as a Burp suite tab. */
    public JComponent getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(0, 6));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        // ── Header (above all sub-tabs, always visible) ──────────────────────
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JLabel nameLbl = new JLabel("SecretSifter");
        nameLbl.setFont(nameLbl.getFont().deriveFont(Font.BOLD, 22f));
        nameLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel tagLbl = new JLabel("Live Credentials & Secrets Scanner");
        tagLbl.setFont(tagLbl.getFont().deriveFont(Font.PLAIN, 13f));
        tagLbl.setForeground(Color.GRAY);
        tagLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        headerPanel.add(nameLbl);
        headerPanel.add(Box.createVerticalStrut(2));
        headerPanel.add(tagLbl);
        rootPanel.add(headerPanel, BorderLayout.NORTH);

        // ── Sub-tab pane ──────────────────────────────────────────────────────
        JTabbedPane subTabs = new JTabbedPane();

        // ═══════════════════════════════════════════════════════════════════
        // TAB 1 — Scanner   (controls + 3 filter columns)
        // ═══════════════════════════════════════════════════════════════════
        JPanel scannerTab = new JPanel(new BorderLayout(4, 6));
        scannerTab.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        topPanel.setBorder(new TitledBorder("Scanner Controls"));

        enabledBox = new ToggleSwitch("Enable passive scanning", settings.isEnabled());
        topPanel.add(enabledBox);

        topPanel.add(new JLabel("   Entropy threshold:"));
        SpinnerNumberModel model = new SpinnerNumberModel(
                settings.getEntropyThreshold(), 0.0, 6.0, 0.1);
        entropySpinner = new JSpinner(model);
        ((JSpinner.NumberEditor) entropySpinner.getEditor()).getFormat().setMaximumFractionDigits(1);
        entropySpinner.setPreferredSize(new Dimension(65, 24));
        entropySpinner.setToolTipText("Shannon entropy threshold (bits/char). Default: 3.5");
        topPanel.add(entropySpinner);

        piiBox = new ToggleSwitch("Enable PII detection (SSN, Credit Cards)", settings.isPiiEnabled());
        topPanel.add(piiBox);

        scanRequestsBox = new ToggleSwitch("Scan request headers / body for secrets", settings.isScanRequestsEnabled());
        scanRequestsBox.setToolTipText(
                "When enabled, scans outbound request headers (X-API-Key, Authorization, etc.) " +
                "and request bodies for hardcoded vendor tokens. " +
                "JWT Bearer tokens are automatically skipped. " +
                "Disable to reduce noise on high-traffic proxies.");
        topPanel.add(scanRequestsBox);

        allowInsecureSslBox = new ToggleSwitch("Allow insecure SSL (trust all certificates)", settings.isAllowInsecureSsl());
        allowInsecureSslBox.setToolTipText(
                "Saved for reference — SSL trust is now governed by Burp's project-level TLS settings " +
                "(Project Options > TLS > Server TLS Certificates). " +
                "For self-signed or internal certs, add the CA to Burp's trust store instead of enabling this option.");
        topPanel.add(allowInsecureSslBox);

        JLabel sslWarnLabel = new JLabel("  \u26a0 Disable only against trusted targets");
        sslWarnLabel.setForeground(new Color(180, 60, 0));
        sslWarnLabel.setFont(sslWarnLabel.getFont().deriveFont(Font.PLAIN, 11f));
        topPanel.add(sslWarnLabel);

        scannerTab.add(topPanel, BorderLayout.NORTH);

        // CDN blocklist
        JPanel cdnPanel = new JPanel(new BorderLayout(4, 4));
        cdnPanel.setBorder(new TitledBorder(
                "CDN / Third-Party Blocklist  (one entry per line — partial host match)"));
        cdnArea = new JTextArea(String.join("\n", settings.getCdnBlocklist()), 8, 20);
        cdnArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cdnArea.setToolTipText("Responses from hosts matching any of these strings are skipped.");
        cdnPanel.add(new JScrollPane(cdnArea), BorderLayout.CENTER);
        cdnPanel.add(makeSearchBar(cdnArea), BorderLayout.SOUTH);

        // Key Name Blocklist
        JPanel keyBlockPanel = new JPanel(new BorderLayout(4, 4));
        keyBlockPanel.setBorder(new TitledBorder(
                "Key Name Blocklist  (suppress — one pattern per line, substring match)"));
        keyBlocklistArea = new JTextArea(String.join("\n", settings.getKeyBlocklist()), 8, 20);
        keyBlocklistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyBlocklistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are suppressed. " +
                "Example: add STORAGE_KEY_ to hide all localStorage constant names. " +
                "Allowlisted keys override this list.");
        keyBlockPanel.add(new JScrollPane(keyBlocklistArea), BorderLayout.CENTER);
        keyBlockPanel.add(makeSearchBar(keyBlocklistArea), BorderLayout.SOUTH);

        // Key Name Allowlist
        JPanel keyAllowPanel = new JPanel(new BorderLayout(4, 4));
        keyAllowPanel.setBorder(new TitledBorder(
                "Key Name Allowlist  (force-report — one pattern per line, substring match)"));
        keyAllowlistArea = new JTextArea(String.join("\n", settings.getKeyAllowlist()), 8, 20);
        keyAllowlistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyAllowlistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are always reported, " +
                "even if the value fails entropy checks. " +
                "Example: add APIM_KEY to ensure all APIM key names are captured.");
        keyAllowPanel.add(new JScrollPane(keyAllowlistArea), BorderLayout.CENTER);
        keyAllowPanel.add(makeSearchBar(keyAllowlistArea), BorderLayout.SOUTH);

        JPanel filterRow = new JPanel(new GridLayout(1, 3, 8, 0));
        filterRow.add(cdnPanel);
        filterRow.add(keyBlockPanel);
        filterRow.add(keyAllowPanel);
        scannerTab.add(filterRow, BorderLayout.CENTER);

        subTabs.addTab("Scanner", scannerTab);

        // ═══════════════════════════════════════════════════════════════════
        // TAB 2 — Custom Rules
        // ═══════════════════════════════════════════════════════════════════
        JPanel customRulesTab = new JPanel(new BorderLayout(4, 6));
        customRulesTab.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));

        JLabel noiseWarning = new JLabel(
                "\u26a0  Custom regex rules run without key-name filtering and may produce noise. " +
                "Review all findings with a CUSTOM_ rule ID carefully before reporting.");
        noiseWarning.setForeground(new Color(160, 80, 0));
        noiseWarning.setFont(noiseWarning.getFont().deriveFont(Font.PLAIN, 11f));
        noiseWarning.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 140, 0), 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        noiseWarning.setOpaque(true);
        noiseWarning.setBackground(new Color(255, 251, 230));
        customRulesTab.add(noiseWarning, BorderLayout.NORTH);

        List<String> savedRules = settings.getCustomRules();
        customRulesArea = new JTextArea(savedRules.isEmpty()
                ? CUSTOM_RULES_PLACEHOLDER
                : String.join("\n", savedRules), 10, 80);
        customRulesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        customRulesArea.setToolTipText(
                "Add your own detection patterns on top of the built-in rules. " +
                "Format: RuleName | regex | severity  (severity: HIGH / MEDIUM / LOW / INFORMATION). " +
                "Example:  MyInternalToken | [A-Z]{3}-[0-9]{10}-[a-z]{5} | HIGH");
        customRulesTab.add(new JScrollPane(customRulesArea), BorderLayout.CENTER);

        JPanel customRulesBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton importRulesBtn = new JButton("Import from file\u2026");
        JButton exportRulesBtn = new JButton("Export to file\u2026");
        importRulesBtn.addActionListener(e -> onImportCustomRules());
        exportRulesBtn.addActionListener(e -> onExportCustomRules());
        customRulesEnabledBox = new ToggleSwitch("Enable custom rules", settings.isCustomRulesEnabled());
        customRulesEnabledBox.setToolTipText("Uncheck to keep imported rules stored but not run during scans.");
        customRulesOnlyBox = new ToggleSwitch("Custom rules only (raw)", settings.isCustomRulesOnly());
        customRulesOnlyBox.setToolTipText(
                "Raw mode: only custom rules run, FP filters bypassed. Allow/block/CDN lists still apply.");
        customRulesBtnBar.add(importRulesBtn);
        customRulesBtnBar.add(exportRulesBtn);
        customRulesBtnBar.add(Box.createHorizontalStrut(12));
        customRulesBtnBar.add(customRulesEnabledBox);
        customRulesBtnBar.add(Box.createHorizontalStrut(12));
        customRulesBtnBar.add(customRulesOnlyBox);

        JPanel customRulesBottom = new JPanel();
        customRulesBottom.setLayout(new BoxLayout(customRulesBottom, BoxLayout.Y_AXIS));
        customRulesBottom.add(makeSearchBar(customRulesArea));
        customRulesBottom.add(customRulesBtnBar);
        customRulesTab.add(customRulesBottom, BorderLayout.SOUTH);

        subTabs.addTab("Custom Rules", customRulesTab);

        // ═══════════════════════════════════════════════════════════════════
        // TAB 3 — AI Triage  (always visible)
        // ═══════════════════════════════════════════════════════════════════
        {
            JPanel aiTab = new JPanel(new BorderLayout(8, 6));
            aiTab.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

            JPanel ctrlPanel = new JPanel();
            ctrlPanel.setLayout(new BoxLayout(ctrlPanel, BoxLayout.Y_AXIS));
            ctrlPanel.setBorder(new TitledBorder("AI Provider"));

            // Provider row
            JPanel provRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            provRow.add(new JLabel("Provider:"));
            java.util.List<String> provOpts = new java.util.ArrayList<>(
                    java.util.Arrays.asList("Burp AI (Pro)", "Anthropic API (Claude)", "OpenAI / Compatible"));
            if (withMcp) provOpts.add("Claude via MCP");
            aiProviderCombo = new JComboBox<>(provOpts.toArray(new String[0]));
            aiProviderCombo.setToolTipText("AI backend used by the 'AI Triage All' button");
            provRow.add(aiProviderCombo);
            ctrlPanel.add(provRow);

            // API key row
            aiKeyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            aiKeyRow.add(new JLabel("API Key:"));
            aiApiKeyField = new JPasswordField(32);
            aiApiKeyField.setToolTipText("Anthropic or OpenAI API key");
            JButton showKeyBtn = new JButton("Show");
            showKeyBtn.addActionListener(e -> {
                boolean shown = aiApiKeyField.getEchoChar() == 0;
                aiApiKeyField.setEchoChar(shown ? '\u25cf' : (char) 0);
                showKeyBtn.setText(shown ? "Show" : "Hide");
            });
            aiKeyRow.add(aiApiKeyField);
            aiKeyRow.add(showKeyBtn);
            ctrlPanel.add(aiKeyRow);

            // Endpoint row
            aiEndpointRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            aiEndpointRow.add(new JLabel("Endpoint:"));
            aiEndpointField = new JTextField("https://api.openai.com/v1/chat/completions", 38);
            aiEndpointField.setToolTipText("OpenAI-compatible endpoint URL (leave default for OpenAI)");
            aiEndpointRow.add(aiEndpointField);
            ctrlPanel.add(aiEndpointRow);

            // Model row
            aiModelRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            aiModelRow.add(new JLabel("Model:    "));
            aiModelField = new JTextField("gpt-4o", 22);
            aiModelField.setToolTipText("Model name (e.g. gpt-4o, gpt-4-turbo)");
            aiModelRow.add(aiModelField);
            ctrlPanel.add(aiModelRow);

            aiProviderCombo.addActionListener(e -> syncAiProviderVisibility());
            syncAiProviderVisibility();

            JTextArea notesArea = new JTextArea(
                "How AI Triage Works\n" +
                "─────────────────────────────────────────────────────────────────\n" +
                "1. Click 'AI Triage All' in the Bulk Scan tab.\n" +
                "2. Every finding is sent to the selected AI to validate real vs noise.\n" +
                "3. Confirmed real findings get severity adjusted by deterministic rules:\n" +
                "     AppKey*          → CRITICAL\n" +
                "     ResourceKey*     → HIGH\n" +
                "     SubscriptionKey* → HIGH\n" +
                "     AppId            → INFORMATION\n" +
                "     JWT from JSON API→ CRITICAL\n" +
                "   All others use the AI's suggested severity.\n" +
                "4. Noise findings are highlighted amber in the table.\n" +
                "5. A review dialog lists them — you choose which to delete.\n\n" +
                "Providers:\n" +
                "  Burp AI         — built-in, Pro only, no key needed\n" +
                "  Anthropic API   — paste your API key above\n" +
                "  OpenAI          — paste your key, set endpoint/model\n" +
                "  Claude via MCP  — Claude Code calls secretsifter_get_triage_request\n" +
                "                    then submits results via secretsifter_submit_triage_results\n",
                10, 55);
            notesArea.setEditable(false);
            notesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            notesArea.setBackground(new Color(252, 252, 252));
            notesArea.setLineWrap(true);
            notesArea.setWrapStyleWord(true);
            JPanel notesPanel = new JPanel(new BorderLayout());
            notesPanel.setBorder(new TitledBorder("How It Works"));
            notesPanel.add(new JScrollPane(notesArea), BorderLayout.CENTER);

            aiTab.add(ctrlPanel,  BorderLayout.NORTH);
            aiTab.add(notesPanel, BorderLayout.CENTER);
            subTabs.addTab("AI Triage", aiTab);
        }

        // ═══════════════════════════════════════════════════════════════════
        // TAB 4 — AI / MCP  (full build only)
        // ═══════════════════════════════════════════════════════════════════
        if (withMcp) {
            JPanel mcpTab = new JPanel(new BorderLayout(8, 6));
            mcpTab.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));

            // ── Top row: enable toggle + live token label ──────────────────
            JPanel mcpTopRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            mcpEnabledBox = new ToggleSwitch(
                    "Enable MCP server on 127.0.0.1:8765  (allows Claude and other AI tools to drive scans)",
                    settings.isMcpEnabled());
            mcpEnabledBox.setToolTipText(
                    "Starts a local JSON-RPC server so AI assistants (Claude, Copilot, etc.) can start " +
                    "scans, read findings, and export reports programmatically via the MCP protocol. " +
                    "Server binds to loopback only; a random auth token is required on every request.");
            mcpTopRow.add(mcpEnabledBox);
            mcpTokenLabel = new JLabel("Token: (enable to generate)");
            mcpTokenLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            mcpTokenLabel.setForeground(Color.GRAY);
            mcpTopRow.add(mcpTokenLabel);
            mcpTab.add(mcpTopRow, BorderLayout.NORTH);

            // ── Left: JSON config snippet + action buttons inside ─────────
            mcpConfigArea = new JTextArea(buildMcpConfigJson("(enable server to generate token)"), 12, 40);
            mcpConfigArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            mcpConfigArea.setEditable(false);
            mcpConfigArea.setBackground(new Color(245, 245, 245));
            mcpConfigArea.setToolTipText(
                    "Claude Desktop: paste into ~/Library/Application Support/Claude/claude_desktop_config.json and restart.");

            JPanel configPanel = new JPanel(new BorderLayout(4, 4));
            configPanel.setBorder(new TitledBorder("Config Snippet"));
            configPanel.add(new JScrollPane(mcpConfigArea), BorderLayout.CENTER);

            // Buttons sit inside configPanel.SOUTH — mirrors "Download Setup Guide" in notesPanel
            JPanel configBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            JButton copyJsonBtn    = new JButton("Copy JSON");
            JButton copyCliBtn     = new JButton("Copy CLI Command");
            JButton saveSnippetBtn = new JButton("Save to file\u2026");
            JButton regenBtn       = new JButton("Regenerate Token");
            copyJsonBtn.setToolTipText("Claude Desktop: copies the mcpServers JSON block to paste into claude_desktop_config.json");
            copyCliBtn.setToolTipText("Claude Code CLI: copies the 'claude mcp add' command — run it once in your terminal");
            saveSnippetBtn.setToolTipText("Save the JSON config snippet as a .json file");
            regenBtn.setToolTipText("Generate a new auth token and save it permanently. Update your Claude config after regenerating.");
            copyJsonBtn.addActionListener(e -> onCopyMcpJson());
            copyCliBtn.addActionListener(e  -> onCopyMcpCliCommand());
            saveSnippetBtn.addActionListener(e -> onSaveMcpSnippet());
            regenBtn.addActionListener(e -> {
                if (mcpBridge == null) {
                    statusLabel.setText("Enable and save MCP server first to generate a token.");
                    statusLabel.setForeground(Color.ORANGE.darker());
                    return;
                }
                String newTok = mcpBridge.regenerateToken();
                mcpTokenLabel.setText("Token: " + newTok);
                mcpTokenLabel.setForeground(new Color(0, 110, 0));
                if (mcpConfigArea != null) mcpConfigArea.setText(buildMcpConfigJson(newTok));
                statusLabel.setText("Token regenerated — update your Claude config with the new token.");
                statusLabel.setForeground(new Color(180, 90, 0));
            });
            configBtnBar.add(copyJsonBtn);
            configBtnBar.add(copyCliBtn);
            configBtnBar.add(saveSnippetBtn);
            configBtnBar.add(regenBtn);
            configPanel.add(configBtnBar, BorderLayout.SOUTH);

            // ── Right: Setup & Troubleshooting notes + download button ────
            JTextArea setupNotesArea = new JTextArea(buildSetupNotes());
            setupNotesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            setupNotesArea.setEditable(false);
            setupNotesArea.setLineWrap(true);
            setupNotesArea.setWrapStyleWord(true);
            setupNotesArea.setBackground(new Color(252, 252, 252));

            JPanel notesPanel = new JPanel(new BorderLayout(4, 4));
            notesPanel.setBorder(new TitledBorder("Setup & Troubleshooting Notes"));
            JScrollPane notesScroll = new JScrollPane(setupNotesArea);
            notesScroll.getVerticalScrollBar().setUnitIncrement(16);
            notesPanel.add(notesScroll, BorderLayout.CENTER);

            JPanel notesBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            JButton downloadNotesBtn = new JButton("Download Setup Guide\u2026");
            downloadNotesBtn.setToolTipText("Save the full setup and troubleshooting guide as a text file");
            downloadNotesBtn.addActionListener(e -> {
                JFileChooser chooser = new JFileChooser();
                chooser.setDialogTitle("Save MCP Setup Guide");
                chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                        "Text files (*.txt)", "txt"));
                chooser.setSelectedFile(new File(
                        System.getProperty("user.home"), "secretsifter-mcp-setup.txt"));
                if (chooser.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
                try {
                    Files.write(chooser.getSelectedFile().toPath(),
                            setupNotesArea.getText()
                                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    statusLabel.setText("Setup guide saved to " +
                            chooser.getSelectedFile().getName());
                    statusLabel.setForeground(new Color(0, 130, 0));
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(rootPanel,
                            "Failed to save: " + ex.getMessage(),
                            "Save Error", JOptionPane.ERROR_MESSAGE);
                }
            });
            notesBtnBar.add(downloadNotesBtn);
            notesPanel.add(notesBtnBar, BorderLayout.SOUTH);

            // ── Split: config (left, 50%) | notes (right, 50%) ───────────
            JSplitPane splitPane = new JSplitPane(
                    JSplitPane.HORIZONTAL_SPLIT, configPanel, notesPanel);
            splitPane.setResizeWeight(0.5);
            splitPane.setDividerSize(6);
            splitPane.setOneTouchExpandable(true);
            splitPane.addComponentListener(new java.awt.event.ComponentAdapter() {
                @Override
                public void componentResized(java.awt.event.ComponentEvent e) {
                    splitPane.removeComponentListener(this);
                    SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
                }
            });
            mcpTab.add(splitPane, BorderLayout.CENTER);

            subTabs.addTab("AI / MCP", mcpTab);
        }

        rootPanel.add(subTabs, BorderLayout.CENTER);

        // ── Save/Reset — always visible below the sub-tabs ───────────────────
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton saveBtn  = new JButton("Save Settings");
        JButton resetBtn = new JButton("Reset to Defaults");
        saveBtn.addActionListener(e  -> onSave());
        resetBtn.addActionListener(e -> onReset());
        statusLabel = new JLabel("Ready.");
        statusLabel.setForeground(Color.GRAY);
        bottomPanel.add(saveBtn);
        bottomPanel.add(resetBtn);
        bottomPanel.add(Box.createHorizontalStrut(20));
        bottomPanel.add(statusLabel);
        rootPanel.add(bottomPanel, BorderLayout.SOUTH);

        settingsScrollPane = null; // no outer scroll — each tab manages its own viewport
    }

    // =========================================================================
    // MCP setup notes
    // =========================================================================

    private static String buildSetupNotes() {
        return
"═══════════════════════════════════════════════════════════════\n" +
"  SecretSifter  —  MCP Setup & Troubleshooting Guide\n" +
"═══════════════════════════════════════════════════════════════\n" +
"\n" +
"QUICK SETUP  —  Claude Code (CLI)\n" +
"─────────────────────────────────\n" +
"1. Enable the MCP server with the toggle above.\n" +
"2. Click \"Copy CLI Command\" and run it in your terminal:\n" +
"\n" +
"   claude mcp add --transport http secretsifter \\\n" +
"     http://127.0.0.1:8765/mcp \\\n" +
"     --header \"Authorization: Bearer <your-token>\"\n" +
"\n" +
"3. Restart Claude Code (exit and reopen, or start a new session).\n" +
"   MCP servers are only loaded at session start — a running session\n" +
"   won't pick up a newly registered server without a restart.\n" +
"\n" +
"4. Verify the connection:\n" +
"   claude mcp list\n" +
"   → secretsifter: ✓ Connected\n" +
"\n" +
"   (Use 'Copy CLI Command' to get the exact command with your\n" +
"    live token already filled in.)\n" +
"\n" +
"QUICK SETUP  —  Claude Desktop\n" +
"───────────────────────────────\n" +
"1. Click \"Copy JSON\" to copy the mcpServers block.\n" +
"2. Paste into:\n" +
"   macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json\n" +
"   Windows: %APPDATA%\\Claude\\claude_desktop_config.json\n" +
"3. Restart Claude Desktop.\n" +
"\n" +
"REGISTRATION COMMANDS\n" +
"──────────────────────\n" +
"Add / register:\n" +
"  claude mcp add --transport http secretsifter \\\n" +
"    http://127.0.0.1:8765/mcp \\\n" +
"    --header \"Authorization: Bearer <your-token>\"\n" +
"\n" +
"Remove:\n" +
"  claude mcp remove secretsifter\n" +
"\n" +
"List all registered servers:\n" +
"  claude mcp list\n" +
"\n" +
"WINDOWS NOTES\n" +
"─────────────\n" +
"PowerShell (use backtick for line continuation):\n" +
"  claude mcp add --transport http secretsifter `\n" +
"    http://127.0.0.1:8765/mcp `\n" +
"    --header \"Authorization: Bearer <your-token>\"\n" +
"\n" +
"cmd.exe (set variable first to avoid quote issues):\n" +
"  set SS_TOKEN=<your-token>\n" +
"  claude mcp add --transport http secretsifter ^\n" +
"    http://127.0.0.1:8765/mcp ^\n" +
"    --header \"Authorization: Bearer %SS_TOKEN%\"\n" +
"\n" +
"TRIAGING  —  \"Failed to connect\"\n" +
"──────────────────────────────────\n" +
"□ Is the MCP server toggle enabled above?\n" +
"□ Did you restart Claude after running 'claude mcp add'?\n" +
"  MCP servers are only loaded at session start — a running session\n" +
"  won't pick up newly registered servers without a restart.\n" +
"□ Is Burp Suite running? The server only runs while Burp is open.\n" +
"□ Token mismatch? (happens after extension reload or Regenerate Token)\n" +
"  Fix: remove and re-register:\n" +
"    claude mcp remove secretsifter\n" +
"    (click 'Copy CLI Command' and re-run)\n" +
"□ Port conflict on 8765? Check if another process is listening.\n" +
"□ Test the server manually with curl:\n" +
"\n" +
"  curl -s -X POST http://127.0.0.1:8765/mcp \\\n" +
"    -H \"Content-Type: application/json\" \\\n" +
"    -H \"Authorization: Bearer <your-token>\" \\\n" +
"    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"," +
"\"params\":{\"protocolVersion\":\"2024-11-05\"," +
"\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}'\n" +
"\n" +
"  Expected: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{...}}\n" +
"  If you get 401: token is wrong — regenerate and re-register.\n" +
"  If connection refused: server is not running — check the toggle.\n" +
"\n" +
"AVAILABLE MCP TOOLS\n" +
"────────────────────\n" +
"scan_url(url)           Scan a single URL for exposed secrets\n" +
"scan_bulk(urls)         Scan a list of URLs (array of strings)\n" +
"get_findings()          Return all current findings as JSON\n" +
"get_findings_csv()      Export findings as CSV text\n" +
"get_findings_html()     Export findings as an HTML report\n" +
"clear_findings()        Clear the findings table\n" +
"get_scan_status()       Check if a scan is running / get progress\n" +
"stop_scan()             Stop the active scan\n" +
"\n" +
"EXAMPLE CLAUDE PROMPTS\n" +
"───────────────────────\n" +
"\"Scan https://app.example.com for exposed secrets.\"\n" +
"\"Bulk scan these URLs and give me a summary: [url1, url2, ...]\"\n" +
"\"Get all findings and export as an HTML report.\"\n" +
"\"How many HIGH severity findings are there?\"\n" +
"\"Stop the current scan.\"\n" +
"\"Clear findings and start a fresh scan of https://target.com\"\n" +
"\n" +
"TOKEN LIFECYCLE\n" +
"────────────────\n" +
"• The token is stored in Burp's preference store.\n" +
"• It survives extension reloads and Burp restarts.\n" +
"• You only need to re-register when:\n" +
"  - You click 'Regenerate Token'\n" +
"  - You click 'Reset to Defaults'\n" +
"  - Burp's preference store is cleared\n" +
"\n" +
"SCOPE OF ACCESS\n" +
"────────────────\n" +
"• The MCP server binds to 127.0.0.1 only (loopback).\n" +
"• No inbound connections are possible from the network.\n" +
"• The auth token is required on every request.\n" +
"• Only Claude (or another local AI client) can connect.\n";
    }

    // =========================================================================
    // Actions
    // =========================================================================

    private void syncAiProviderVisibility() {
        if (aiProviderCombo == null) return;
        int sel = aiProviderCombo.getSelectedIndex();
        // 0=Burp AI, 1=Anthropic, 2=OpenAI, 3=MCP (withMcp only)
        boolean needKey      = sel == 1 || sel == 2;
        boolean needEndpoint = sel == 2;
        if (aiKeyRow      != null) aiKeyRow.setVisible(needKey);
        if (aiEndpointRow != null) aiEndpointRow.setVisible(needEndpoint);
        if (aiModelRow    != null) aiModelRow.setVisible(needEndpoint);
    }

    private void onSave() {
        // 1. Read controls into settings
        settings.setEnabled(enabledBox.isSelected());
        settings.setEntropyThreshold(((Number) entropySpinner.getValue()).doubleValue());
        settings.setPiiEnabled(piiBox.isSelected());
        settings.setScanRequestsEnabled(scanRequestsBox.isSelected());
        settings.setAllowInsecureSsl(allowInsecureSslBox.isSelected());
        settings.setCustomRulesEnabled(customRulesEnabledBox.isSelected());
        settings.setCustomRulesOnly(customRulesOnlyBox.isSelected());

        if (aiProviderCombo != null) {
            AiTriageProvider.Provider[] map = {
                AiTriageProvider.Provider.BURP,
                AiTriageProvider.Provider.ANTHROPIC,
                AiTriageProvider.Provider.OPENAI,
                AiTriageProvider.Provider.MCP
            };
            int idx = aiProviderCombo.getSelectedIndex();
            if (idx >= 0 && idx < map.length) settings.setAiProvider(map[idx]);
        }
        if (aiApiKeyField   != null) settings.setAiApiKey(new String(aiApiKeyField.getPassword()));
        if (aiEndpointField != null) settings.setAiEndpoint(aiEndpointField.getText().trim());
        if (aiModelField    != null) settings.setAiModel(aiModelField.getText().trim());

        if (withMcp && mcpEnabledBox != null) {
            boolean mcpWasEnabled = settings.isMcpEnabled();
            settings.setMcpEnabled(mcpEnabledBox.isSelected());
            if (mcpBridge != null) {
                if (settings.isMcpEnabled() && !mcpWasEnabled) {
                    mcpBridge.start();
                    String tok = mcpBridge.getToken();
                    mcpTokenLabel.setText("Token: " + tok);
                    mcpTokenLabel.setForeground(new Color(0, 110, 0));
                    if (mcpConfigArea != null) mcpConfigArea.setText(buildMcpConfigJson(tok));
                } else if (!settings.isMcpEnabled() && mcpWasEnabled) {
                    mcpBridge.stop();
                    mcpTokenLabel.setText("Token: (server stopped)");
                    mcpTokenLabel.setForeground(Color.GRAY);
                    if (mcpConfigArea != null)
                        mcpConfigArea.setText(buildMcpConfigJson("(server stopped \u2014 re-enable to get a new token)"));
                }
            }
        }

        List<String> cdn = new ArrayList<>();
        for (String line : cdnArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) cdn.add(trimmed);
        }
        settings.setCdnBlocklist(cdn);

        List<String> keyBlock = new ArrayList<>();
        for (String line : keyBlocklistArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) keyBlock.add(trimmed);
        }
        settings.setKeyBlocklist(keyBlock);

        List<String> keyAllow = new ArrayList<>();
        for (String line : keyAllowlistArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) keyAllow.add(trimmed);
        }
        settings.setKeyAllowlist(keyAllow);

        List<String> customRules = new ArrayList<>();
        for (String line : customRulesArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) customRules.add(trimmed);
        }
        settings.setCustomRules(customRules);

        // 2. Persist to Burp preferences
        settings.saveToPreferences(api);

        // Count valid vs broken custom rules and surface in status bar
        int validRules = 0, brokenRules = 0;
        for (String line : customRules) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] parts = line.split(" \\| ", 3);
            if (parts.length < 3) { brokenRules++; continue; }
            try { java.util.regex.Pattern.compile(parts[1].trim()); validRules++; }
            catch (Exception ignored) { brokenRules++; }
        }
        String rulesInfo = validRules + " custom rule" + (validRules != 1 ? "s" : "") + " active";
        if (brokenRules > 0) rulesInfo += "  ⚠ " + brokenRules + " invalid (check Burp Extensions output)";

        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        statusLabel.setText("Saved at " + time + "   [entropy=" +
                String.format("%.1f", settings.getEntropyThreshold()) +
                "  pii=" + settings.isPiiEnabled() +
                "  " + rulesInfo + "]");
        statusLabel.setForeground(brokenRules > 0 ? new Color(180, 90, 0) : new Color(0, 130, 0));
    }

    private void onImportCustomRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Custom Rules");
        chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        chooser.setMultiSelectionEnabled(true);
        if (chooser.showOpenDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File[] files = chooser.getSelectedFiles();
        if (files == null || files.length == 0) return;
        StringBuilder sb = new StringBuilder();
        String existing = customRulesArea.getText().trim();
        if (!existing.isEmpty() && !existing.equals(CUSTOM_RULES_PLACEHOLDER.trim())) {
            sb.append(existing).append("\n");
        }
        List<String> imported = new ArrayList<>();
        for (File f : files) {
            try {
                String content = new String(Files.readAllBytes(f.toPath())).trim();
                if (!content.isEmpty()) {
                    sb.append(content).append("\n");
                    imported.add(f.getName());
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(rootPanel,
                        "Failed to read file: " + ex.getMessage(),
                        "Import Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        customRulesArea.setText(sb.toString().trim());
        // Count non-comment rule lines across all imported content to give feedback
        long ruleCount = java.util.Arrays.stream(sb.toString().split("\n"))
                .map(String::trim)
                .filter(l -> !l.isEmpty() && !l.startsWith("#") && l.contains(" | "))
                .count();
        String names = String.join(", ", imported);
        statusLabel.setText("Imported " + imported.size() + " file(s) (" + ruleCount +
                " rule lines): " + names + " — click Save to apply.");
        statusLabel.setForeground(new Color(0, 100, 180));
    }

    private void onExportCustomRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Custom Rules");
        chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        chooser.setSelectedFile(new File("secretsifter-custom-rules.txt"));
        if (chooser.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        try {
            File f = chooser.getSelectedFile();
            Files.write(f.toPath(), customRulesArea.getText().getBytes());
            statusLabel.setText("Exported rules to " + f.getName());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to write file: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onReset() {
        int confirm = JOptionPane.showConfirmDialog(rootPanel,
                "Reset all settings to defaults?", "Confirm Reset",
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        settings.resetToDefaults();
        enabledBox.setSelected(settings.isEnabled());
        entropySpinner.setValue(settings.getEntropyThreshold());
        piiBox.setSelected(settings.isPiiEnabled());
        scanRequestsBox.setSelected(settings.isScanRequestsEnabled());
        allowInsecureSslBox.setSelected(settings.isAllowInsecureSsl());
        cdnArea.setText(String.join("\n", settings.getCdnBlocklist()));
        keyBlocklistArea.setText(String.join("\n", settings.getKeyBlocklist()));
        keyAllowlistArea.setText(String.join("\n", settings.getKeyAllowlist()));
        customRulesArea.setText(CUSTOM_RULES_PLACEHOLDER);
        customRulesEnabledBox.setSelected(settings.isCustomRulesEnabled());
        if (customRulesOnlyBox != null) customRulesOnlyBox.setSelected(settings.isCustomRulesOnly());
        if (withMcp && mcpEnabledBox != null) {
            mcpEnabledBox.setSelected(settings.isMcpEnabled());
            mcpTokenLabel.setText("Token: (enable to generate)");
            mcpTokenLabel.setForeground(Color.GRAY);
            if (mcpConfigArea != null)
                mcpConfigArea.setText(buildMcpConfigJson("(enable server to generate token)"));
        }
        statusLabel.setText("Reset to defaults.");
        statusLabel.setForeground(Color.GRAY);
    }

    // =========================================================================
    // Public load method — called from SecretScannerExtension after init
    // =========================================================================

    // =========================================================================
    // Search bar helper
    // =========================================================================

    /**
     * Returns a compact search bar panel for the given text area.
     * As the user types, matching lines are highlighted and a Found / Not found
     * indicator is shown — useful for checking whether an entry already exists
     * before adding it to the list.
     */
    private JPanel makeSearchBar(JTextArea area) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        bar.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        JLabel lbl = new JLabel("Search:");
        lbl.setFont(lbl.getFont().deriveFont(Font.PLAIN, 11f));

        JTextField field = new JTextField(16);
        field.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        field.setToolTipText("Type to search. Press Enter to cycle through matches.");

        JLabel result = new JLabel(" ");
        result.setFont(result.getFont().deriveFont(Font.BOLD, 11f));

        bar.add(lbl);
        bar.add(field);
        bar.add(result);

        Highlighter highlighter = area.getHighlighter();
        Highlighter.HighlightPainter allPainter =
                new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 230, 80));
        Highlighter.HighlightPainter currentPainter =
                new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 140, 0));

        List<Integer> matchPositions = new ArrayList<>();
        int[] currentMatch = {0};

        Runnable repaintHighlights = () -> {
            highlighter.removeAllHighlights();
            int len = field.getText().trim().length();
            if (len == 0 || matchPositions.isEmpty()) return;
            for (int i = 0; i < matchPositions.size(); i++) {
                int pos = matchPositions.get(i);
                try {
                    highlighter.addHighlight(pos, pos + len,
                            i == currentMatch[0] ? currentPainter : allPainter);
                } catch (BadLocationException ignored) {}
            }
        };

        Runnable scrollToCurrent = () -> {
            if (matchPositions.isEmpty()) return;
            int pos = matchPositions.get(currentMatch[0]);
            int len = field.getText().trim().length();
            area.setCaretPosition(pos + len);
            area.moveCaretPosition(pos);
            result.setText("\u2713 " + (currentMatch[0] + 1) + " / " + matchPositions.size());
            result.setForeground(new Color(0, 130, 0));
        };

        Runnable doSearch = () -> {
            String query = field.getText().trim();
            matchPositions.clear();
            currentMatch[0] = 0;
            highlighter.removeAllHighlights();
            if (query.isEmpty()) {
                result.setText(" ");
                result.setForeground(Color.GRAY);
                area.select(0, 0);
                return;
            }
            String content = area.getText().toLowerCase();
            String queryLc = query.toLowerCase();
            int idx = 0;
            while ((idx = content.indexOf(queryLc, idx)) >= 0) {
                matchPositions.add(idx);
                idx += queryLc.length();
            }
            if (matchPositions.isEmpty()) {
                result.setText("\u2717 Not found");
                result.setForeground(new Color(180, 0, 0));
                area.select(0, 0);
            } else {
                repaintHighlights.run();
                scrollToCurrent.run();
            }
        };

        field.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { doSearch.run(); }
            public void removeUpdate(DocumentEvent e)  { doSearch.run(); }
            public void changedUpdate(DocumentEvent e) { doSearch.run(); }
        });

        // Enter cycles forward; Shift+Enter cycles backward
        field.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() != KeyEvent.VK_ENTER || matchPositions.isEmpty()) return;
                if (e.isShiftDown()) {
                    currentMatch[0] = (currentMatch[0] - 1 + matchPositions.size()) % matchPositions.size();
                } else {
                    currentMatch[0] = (currentMatch[0] + 1) % matchPositions.size();
                }
                repaintHighlights.run();
                scrollToCurrent.run();
            }
        });

        return bar;
    }

    // =========================================================================
    // MCP helpers
    // =========================================================================

    private String buildMcpConfigJson(String token) {
        return "{\n" +
               "  \"mcpServers\": {\n" +
               "    \"secretsifter\": {\n" +
               "      \"type\": \"http\",\n" +
               "      \"url\": \"http://127.0.0.1:" + McpBridge.PORT + "/mcp\",\n" +
               "      \"headers\": {\n" +
               "        \"Authorization\": \"Bearer " + token + "\"\n" +
               "      }\n" +
               "    }\n" +
               "  }\n" +
               "}";
    }

    private String buildMcpCliCommand(String token) {
        return "claude mcp add --transport http secretsifter " +
               "http://127.0.0.1:" + McpBridge.PORT + "/mcp " +
               "--header \"Authorization: Bearer " + token + "\"";
    }

    private void onCopyMcpCliCommand() {
        if (mcpBridge == null || !settings.isMcpEnabled()) {
            statusLabel.setText("Enable MCP server first to get the CLI command.");
            statusLabel.setForeground(Color.ORANGE.darker());
            return;
        }
        String cmd = buildMcpCliCommand(mcpBridge.getToken());
        java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(cmd);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
        statusLabel.setText("Claude Code CLI command copied — paste into terminal and run once.");
        statusLabel.setForeground(new Color(0, 110, 0));
    }

    private void onCopyMcpJson() {
        if (mcpConfigArea == null) return;
        java.awt.datatransfer.StringSelection sel =
                new java.awt.datatransfer.StringSelection(mcpConfigArea.getText());
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
        statusLabel.setText("MCP config JSON copied to clipboard.");
        statusLabel.setForeground(new Color(0, 130, 0));
    }

    private void onSaveMcpSnippet() {
        if (mcpConfigArea == null) return;
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save MCP Config Snippet");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new File(System.getProperty("user.home"), "secretsifter-mcp.json"));
        if (chooser.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        try {
            File f = chooser.getSelectedFile();
            Files.write(f.toPath(),
                    mcpConfigArea.getText().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            statusLabel.setText("MCP config saved to " + f.getAbsolutePath());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save file: " + ex.getMessage(),
                    "Save Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Called from SecretScannerExtension after McpBridge is constructed. No-op in store build. */
    public void setMcpBridge(McpBridge bridge) {
        if (!withMcp) return;
        this.mcpBridge = bridge;
    }

    /** Updates the token label and config snippet after MCP bridge starts (safe to call from any thread). */
    public void syncMcpToken() {
        if (mcpTokenLabel == null || mcpBridge == null) return;
        if (!settings.isMcpEnabled()) return;
        String tok = mcpBridge.getToken();
        SwingUtilities.invokeLater(() -> {
            mcpTokenLabel.setText("Token: " + tok);
            mcpTokenLabel.setForeground(new Color(0, 110, 0));
            if (mcpConfigArea != null) mcpConfigArea.setText(buildMcpConfigJson(tok));
        });
    }

    public void loadFromPreferences() {
        settings.loadFromPreferences(api);
        if (SwingUtilities.isEventDispatchThread()) {
            syncControlsFromSettings();
        } else {
            SwingUtilities.invokeLater(this::syncControlsFromSettings);
        }
    }

    private void syncControlsFromSettings() {
        if (enabledBox        != null) enabledBox.setSelected(settings.isEnabled());
        if (entropySpinner    != null) entropySpinner.setValue(settings.getEntropyThreshold());
        if (piiBox            != null) piiBox.setSelected(settings.isPiiEnabled());
        if (scanRequestsBox      != null) scanRequestsBox.setSelected(settings.isScanRequestsEnabled());
        if (allowInsecureSslBox  != null) allowInsecureSslBox.setSelected(settings.isAllowInsecureSsl());
        if (cdnArea              != null) cdnArea.setText(String.join("\n", settings.getCdnBlocklist()));
        if (keyBlocklistArea  != null) keyBlocklistArea.setText(String.join("\n", settings.getKeyBlocklist()));
        if (keyAllowlistArea  != null) keyAllowlistArea.setText(String.join("\n", settings.getKeyAllowlist()));
        if (customRulesEnabledBox != null) customRulesEnabledBox.setSelected(settings.isCustomRulesEnabled());
        if (customRulesOnlyBox    != null) customRulesOnlyBox.setSelected(settings.isCustomRulesOnly());
        if (withMcp && mcpEnabledBox != null) mcpEnabledBox.setSelected(settings.isMcpEnabled());
        if (aiProviderCombo != null) {
            int idx = switch (settings.getAiProvider()) {
                case BURP      -> 0;
                case ANTHROPIC -> 1;
                case OPENAI    -> 2;
                case MCP       -> withMcp ? 3 : 0;
                default        -> 0;
            };
            aiProviderCombo.setSelectedIndex(idx);
            syncAiProviderVisibility();
        }
        if (aiApiKeyField   != null) aiApiKeyField.setText(settings.getAiApiKey());
        if (aiEndpointField != null) { String ep = settings.getAiEndpoint(); aiEndpointField.setText(ep.isBlank() ? "https://api.openai.com/v1/chat/completions" : ep); }
        if (aiModelField    != null) { String m = settings.getAiModel(); aiModelField.setText(m.isBlank() ? "gpt-4o" : m); }
        if (customRulesArea != null) {
            List<String> rules = settings.getCustomRules();
            customRulesArea.setText(rules.isEmpty() ? CUSTOM_RULES_PLACEHOLDER : String.join("\n", rules));
        }
        if (statusLabel       != null) statusLabel.setText("Settings loaded from preferences.");
    }

}
