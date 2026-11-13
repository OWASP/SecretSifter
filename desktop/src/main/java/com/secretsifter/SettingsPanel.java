package com.secretsifter;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Settings tab — mirrors the Burp extension SettingsPanel layout.
 * Header + sub-tabs (Scanner | Custom Rules | AI / MCP) + Save/Reset at bottom.
 */
public class SettingsPanel {

    private final ScanSettings settings;
    private final AppPrefs     prefs;
    private final McpServer    mcpServer;

    private JPanel     rootPanel;
    private ToggleSwitch  enabledBox;
    private JComboBox<String> tierCombo;
    private JSpinner   entropySpinner;
    private ToggleSwitch  piiBox;
    private ToggleSwitch  scanRequestsBox;
    private ToggleSwitch  liveValidateBox;
    // Validation sub-tab
    private JTextArea    validationCustomArea;
    private JTextArea    validationBaseUrlArea;
    private javax.swing.table.DefaultTableModel validationModel;
    private java.util.Set<String> validationEnabledIds = new java.util.HashSet<>();
    private java.util.List<com.secretsifter.core.ValidationRule> validationCatalog;
    private JTextArea  cdnArea;
    private JTextArea  keyBlocklistArea;
    private JTextArea  keyAllowlistArea;
    private JLabel     statusLabel;
    // Custom Rules
    private JTextArea    customRulesArea;
    private ToggleSwitch customRulesEnabledBox;
    private ToggleSwitch customRulesOnlyBox;
    // Per-URL timeout
    private JComboBox<String> urlTimeoutCombo;
    // Browser / Playwright
    private ToggleSwitch  pwEnabledBox;
    private JSpinner   maxPagesSpinner;
    private JTextField browserPathField;
    // MCP
    private ToggleSwitch  mcpEnabledBox;
    private JSpinner       mcpPortSpinner;
    private JPasswordField aiKeyField;
    private JToggleButton  showAiKeyBtn;
    private JLabel     mcpTokenLabel;
    private JLabel     mcpStatusLabel;
    private JTextArea  mcpConfigArea;

    private static final String[] URL_TIMEOUT_LABELS  = {
            "No limit", "30s  (0.5 min)", "1 min", "1.5 min", "2 min", "3 min", "5 min"
    };
    private static final int[] URL_TIMEOUT_SECONDS = { 0, 30, 60, 90, 120, 180, 300 };

    private static final String CUSTOM_RULES_PLACEHOLDER =
            "# Format: RuleName | regex | severity  (HIGH / MEDIUM / LOW / INFORMATION)\n" +
            "# Lines starting with # are comments and are ignored by the scanner.\n" +
            "#\n" +
            "# -- Examples (remove the leading # to activate) --\n" +
            "#\n" +
            "# TelegramBotToken | \\b[0-9]{5,16}:A[0-9A-Za-z_-]{34}\\b | HIGH\n" +
            "# HuggingFaceToken | \\bhf_[A-Za-z0-9]{34}\\b | HIGH\n" +
            "# InternalToken    | INT-[0-9]{8}-[A-Z]{4} | HIGH\n";

    private final JComponent proxyTabContent;

    public SettingsPanel(ScanSettings settings, AppPrefs prefs, McpServer mcpServer) {
        this(settings, prefs, mcpServer, null);
    }

    public SettingsPanel(ScanSettings settings, AppPrefs prefs, McpServer mcpServer,
                          JComponent proxyTabContent) {
        this.settings  = settings;
        this.prefs     = prefs;
        this.mcpServer = mcpServer;
        this.proxyTabContent = proxyTabContent;
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

    public JPanel getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(0, 6));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        // ── Header (above all sub-tabs, always visible): OWASP logo + name ────
        JPanel textBlock = new JPanel();
        textBlock.setLayout(new BoxLayout(textBlock, BoxLayout.Y_AXIS));
        textBlock.setOpaque(false);

        JLabel nameLbl = new JLabel("OWASP SecretSifter");
        nameLbl.setFont(nameLbl.getFont().deriveFont(Font.BOLD, 22f));
        nameLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel tagLbl = new JLabel("Live Credentials & Secrets Scanner  —  AI-Powered");
        tagLbl.setFont(tagLbl.getFont().deriveFont(Font.PLAIN, 13f));
        tagLbl.setForeground(Color.GRAY);
        tagLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        textBlock.add(nameLbl);
        textBlock.add(Box.createVerticalStrut(2));
        textBlock.add(tagLbl);

        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.X_AXIS));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        // OWASP mark (owl) to the left of the title
        java.net.URL logoUrl = SettingsPanel.class.getResource("/icon_64.png");
        if (logoUrl != null) {
            Image logo = new ImageIcon(logoUrl).getImage().getScaledInstance(44, 44, Image.SCALE_SMOOTH);
            JLabel logoLbl = new JLabel(new ImageIcon(logo));
            logoLbl.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 12));
            headerPanel.add(logoLbl);
        }
        headerPanel.add(textBlock);
        headerPanel.add(Box.createHorizontalGlue());
        rootPanel.add(headerPanel, BorderLayout.NORTH);

        // ── Sub-tab pane ──────────────────────────────────────────────────────
        JTabbedPane subTabs = new JTabbedPane();

        // ═════════════════════════════════════════════════════════════════════
        // TAB 1 — Scanner
        // ═════════════════════════════════════════════════════════════════════
        JPanel scannerTab = new JPanel(new BorderLayout(4, 6));
        scannerTab.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));

        // Scanner controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        topPanel.setBorder(new TitledBorder("Scanner Controls"));

        enabledBox = new ToggleSwitch("Enable scanning", settings.isEnabled());
        topPanel.add(enabledBox);

        topPanel.add(new JLabel("   Scan Tier:"));
        tierCombo = new JComboBox<>(new String[]{"FULL", "LIGHT", "FAST"});
        tierCombo.setSelectedItem(settings.getTier().name());
        tierCombo.setToolTipText(
                "FULL: all checks (slowest, most thorough)\n" +
                "LIGHT: vendor tokens + DB strings\n" +
                "FAST: vendor tokens + URL creds only");
        topPanel.add(tierCombo);

        topPanel.add(new JLabel("   Entropy threshold:"));
        SpinnerNumberModel entModel = new SpinnerNumberModel(settings.getEntropyThreshold(), 0.0, 6.0, 0.1);
        entropySpinner = new JSpinner(entModel);
        ((JSpinner.NumberEditor) entropySpinner.getEditor()).getFormat().setMaximumFractionDigits(1);
        entropySpinner.setPreferredSize(new Dimension(65, 24));
        entropySpinner.setToolTipText("Shannon entropy threshold (bits/char). Default: 3.5");
        topPanel.add(entropySpinner);

        piiBox = new ToggleSwitch("Enable PII detection (SSN, Credit Cards)", settings.isPiiEnabled());
        topPanel.add(piiBox);

        scanRequestsBox = new ToggleSwitch("Scan request headers for secrets", settings.isScanRequestsEnabled());
        scanRequestsBox.setToolTipText(
                "<html>When enabled, scans outbound request headers (X-API-Key, Authorization, etc.)<br>" +
                "for hardcoded vendor tokens. JWT Bearer tokens are automatically skipped.</html>");
        topPanel.add(scanRequestsBox);
        // (Live-validation opt-in lives on the dedicated "Validation" sub-tab below.)

        topPanel.add(new JLabel("   Per-URL timeout:"));
        urlTimeoutCombo = new JComboBox<>(URL_TIMEOUT_LABELS);
        urlTimeoutCombo.setToolTipText(
                "<html>Maximum wall-clock time per seed URL (including all its script fetches).<br>" +
                "Recommended: <b>1.5 min</b> for large batches.</html>");
        int savedTimeout = settings.getUrlTimeoutSeconds();
        for (int i = 0; i < URL_TIMEOUT_SECONDS.length; i++) {
            if (URL_TIMEOUT_SECONDS[i] == savedTimeout) { urlTimeoutCombo.setSelectedIndex(i); break; }
        }
        topPanel.add(urlTimeoutCombo);

        // Browser / Playwright controls
        JPanel browserPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        browserPanel.setBorder(new TitledBorder("Browser Mode — Playwright (Edge / Chromium)"));

        pwEnabledBox = new ToggleSwitch("Enable headless browser for Bulk Scan", settings.isPlaywrightEnabled());
        pwEnabledBox.setToolTipText(
                "Use a real browser to discover dynamically-loaded JS.\n" +
                "Uses Microsoft Edge automatically on Windows 10/11 — no setup required.\n" +
                "If Edge is not found, Chromium is downloaded automatically (~120 MB, one-time).");
        browserPanel.add(pwEnabledBox);

        browserPanel.add(new JLabel("   Max pages:"));
        maxPagesSpinner = new JSpinner(new SpinnerNumberModel(settings.getPlaywrightMaxPages(), 1, 2000, 10));
        maxPagesSpinner.setPreferredSize(new Dimension(65, 24));
        maxPagesSpinner.setToolTipText("Maximum HTML pages to crawl per seed URL (default 100)");
        browserPanel.add(maxPagesSpinner);

        browserPanel.add(new JLabel("   Browser path:"));
        browserPathField = new JTextField(settings.getBrowserPath(), 28);
        browserPathField.setToolTipText(
                "<html>Full path to browser executable. Leave empty for auto-detect.<br>" +
                "<b>Windows:</b> auto-detects Edge, then falls back to Playwright Chromium.</html>");
        browserPanel.add(browserPathField);

        JButton installBtn = new JButton("Install Instructions\u2026");
        installBtn.addActionListener(e -> showInstallInstructions());
        browserPanel.add(installBtn);

        // Wrap topPanel + browserPanel vertically above the filter grid
        JPanel topWrapper = new JPanel();
        topWrapper.setLayout(new BoxLayout(topWrapper, BoxLayout.Y_AXIS));
        topWrapper.add(topPanel);
        topWrapper.add(browserPanel);
        scannerTab.add(topWrapper, BorderLayout.NORTH);

        // 3-column filter grid: CDN blocklist | Key Blocklist | Key Allowlist
        JPanel cdnPanel = new JPanel(new BorderLayout(4, 4));
        cdnPanel.setBorder(new TitledBorder("CDN / Third-Party Blocklist  (one entry per line — partial host match)"));
        cdnArea = new JTextArea(String.join("\n", settings.getCdnBlocklist()), 8, 20);
        cdnArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cdnArea.setToolTipText("Responses from hosts matching any of these strings are skipped.");
        cdnPanel.add(new JScrollPane(cdnArea), BorderLayout.CENTER);
        cdnPanel.add(makeSearchBar(cdnArea), BorderLayout.SOUTH);

        JPanel keyBlockPanel = new JPanel(new BorderLayout(4, 4));
        keyBlockPanel.setBorder(new TitledBorder("Key Name Blocklist  (suppress — one pattern per line, substring match)"));
        keyBlocklistArea = new JTextArea(String.join("\n", settings.getKeyBlocklist()), 8, 20);
        keyBlocklistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyBlocklistArea.setToolTipText(
                "<html>Findings whose matched key name contains any entry here are suppressed.<br>" +
                "Example: add <b>STORAGE_KEY_</b> to hide all localStorage constant names.<br>" +
                "Allowlisted keys override this list.</html>");
        keyBlockPanel.add(new JScrollPane(keyBlocklistArea), BorderLayout.CENTER);
        keyBlockPanel.add(makeSearchBar(keyBlocklistArea), BorderLayout.SOUTH);

        JPanel keyAllowPanel = new JPanel(new BorderLayout(4, 4));
        keyAllowPanel.setBorder(new TitledBorder("Key Name Allowlist  (force-report — one pattern per line, substring match)"));
        keyAllowlistArea = new JTextArea(String.join("\n", settings.getKeyAllowlist()), 8, 20);
        keyAllowlistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyAllowlistArea.setToolTipText(
                "<html>Findings whose matched key name contains any entry here are always reported,<br>" +
                "even if the value fails entropy checks.</html>");
        keyAllowPanel.add(new JScrollPane(keyAllowlistArea), BorderLayout.CENTER);
        keyAllowPanel.add(makeSearchBar(keyAllowlistArea), BorderLayout.SOUTH);

        JPanel filterRow = new JPanel(new GridLayout(1, 3, 8, 0));
        filterRow.add(cdnPanel);
        filterRow.add(keyBlockPanel);
        filterRow.add(keyAllowPanel);
        scannerTab.add(filterRow, BorderLayout.CENTER);

        subTabs.addTab("Scanner", scannerTab);

        // ═════════════════════════════════════════════════════════════════════
        // TAB 2 — Custom Rules
        // ═════════════════════════════════════════════════════════════════════
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
        customRulesTab.add(noiseWarning, BorderLayout.NORTH);

        List<String> savedRules = settings.getCustomRules();
        customRulesArea = new JTextArea(savedRules.isEmpty()
                ? CUSTOM_RULES_PLACEHOLDER : String.join("\n", savedRules), 10, 80);
        customRulesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        customRulesArea.setToolTipText(
                "Add your own detection patterns. Format: RuleName | regex | severity");
        customRulesTab.add(new JScrollPane(customRulesArea), BorderLayout.CENTER);

        JPanel customRulesBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton importRulesBtn = new JButton("Import from file\u2026");
        JButton exportRulesBtn = new JButton("Export to file\u2026");
        importRulesBtn.addActionListener(e -> onImportCustomRules());
        exportRulesBtn.addActionListener(e -> onExportCustomRules());
        customRulesEnabledBox = new ToggleSwitch("Enable custom rules", settings.isCustomRulesEnabled());
        customRulesEnabledBox.setToolTipText(
                "<html>When enabled, your custom regex rules run <b>in addition to</b> the<br>" +
                "default built-in detection (vendor tokens, GENERIC_KV, JWT, JSON_WALK, etc.).<br>" +
                "Custom rules are additive — they extend coverage, they don't replace it.<br><br>" +
                "To run <i>only</i> your custom rules and skip built-in detection, also turn<br>" +
                "on the \"Use custom rules ONLY\" toggle to the right.</html>");
        customRulesOnlyBox = new ToggleSwitch("Use custom rules ONLY (skip built-in detection)",
                settings.isCustomRulesOnly());
        customRulesOnlyBox.setToolTipText(
                "<html>When enabled, the scanner runs <b>only</b> your custom regex rules and skips<br>" +
                "all built-in vendor / generic detection.<br><br>" +
                "<b>Raw mode:</b> in this mode the default noise filters (placeholder, entropy,<br>" +
                "hex-too-short, key blocklist) are also bypassed — every regex match is reported,<br>" +
                "including false positives.  This is intentional: you've opted into regex-only<br>" +
                "matching and you know your patterns will fire on noise.<br><br>" +
                "Useful for shipping a curated org-specific rule pack and seeing exactly what<br>" +
                "the regex catches without any hidden filtering.</html>");
        customRulesBtnBar.add(importRulesBtn);
        customRulesBtnBar.add(exportRulesBtn);
        customRulesBtnBar.add(Box.createHorizontalStrut(12));
        customRulesBtnBar.add(customRulesEnabledBox);
        customRulesBtnBar.add(Box.createHorizontalStrut(8));
        customRulesBtnBar.add(customRulesOnlyBox);

        JPanel customRulesBottom = new JPanel();
        customRulesBottom.setLayout(new BoxLayout(customRulesBottom, BoxLayout.Y_AXIS));
        customRulesBottom.add(makeSearchBar(customRulesArea));
        customRulesBottom.add(customRulesBtnBar);
        customRulesTab.add(customRulesBottom, BorderLayout.SOUTH);

        subTabs.addTab("Custom Rules", customRulesTab);

        // ═════════════════════════════════════════════════════════════════════
        // TAB — Validation  (choose which findings get validated)
        // ═════════════════════════════════════════════════════════════════════
        {
            JPanel valTab = new JPanel(new BorderLayout(8, 6));
            valTab.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

            JTextArea intro = new JTextArea(
                    "Pick which findings get validated, grouped by provider. Turn validation on from "
                    + "the Scan tab → Validate; it runs the selected offline checks (JWT expiry, Luhn, your "
                    + "regex) and sends nothing anywhere. Live (network) entries send the found key to the "
                    + "provider's endpoint to check if it is still live — that only happens when you enable "
                    + "the switch below and select the provider.");
            intro.setEditable(false);
            intro.setLineWrap(true);
            intro.setWrapStyleWord(true);
            intro.setOpaque(false);
            intro.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
            intro.setFont(UIManager.getFont("Label.font"));
            intro.setForeground(UIManager.getColor("Label.foreground"));
            intro.setFocusable(false);

            validationCatalog = ValidationCatalog.builtIn();
            validationEnabledIds = new java.util.HashSet<>(settings.getValidationEnabledIds());
            String[] vcols = {"On", "Name", "Provider", "Check", "Endpoint (what a live check contacts)"};
            validationModel = new javax.swing.table.DefaultTableModel(vcols, 0) {
                @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
                @Override public boolean isCellEditable(int r, int c) { return false; }
            };
            java.util.Map<String, String> baseMap = settings.validationBaseUrlMap();
            for (com.secretsifter.core.ValidationRule vr : validationCatalog)
                validationModel.addRow(new Object[]{ validationEnabledIds.contains(vr.id()),
                        vr.name(), vr.provider(), vr.check().label(),
                        com.secretsifter.core.ValidationEndpoints.resolve(vr.provider(), baseMap.get(vr.provider())) });
            JTable valTable = new JTable(validationModel);
            valTable.setRowHeight(22);
            javax.swing.table.DefaultTableCellRenderer vplain = new javax.swing.table.DefaultTableCellRenderer();
            vplain.putClientProperty("html.disable", Boolean.TRUE);
            valTable.setDefaultRenderer(String.class, vplain);
            valTable.getColumnModel().getColumn(0).setCellRenderer(new ToggleCellRenderer());
            valTable.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override public void mousePressed(java.awt.event.MouseEvent e) {
                    int vcol = valTable.columnAtPoint(e.getPoint());
                    int vrow = valTable.rowAtPoint(e.getPoint());
                    if (vcol != 0 || vrow < 0) return;
                    int mrow = valTable.convertRowIndexToModel(vrow);
                    boolean cur = Boolean.TRUE.equals(validationModel.getValueAt(mrow, 0));
                    validationModel.setValueAt(!cur, mrow, 0);
                }
            });
            valTable.getColumnModel().getColumn(0).setMaxWidth(44);
            valTable.getColumnModel().getColumn(0).setPreferredWidth(44);
            valTable.getColumnModel().getColumn(1).setPreferredWidth(230);
            valTable.getColumnModel().getColumn(2).setPreferredWidth(130);
            valTable.getColumnModel().getColumn(3).setPreferredWidth(150);
            valTable.getColumnModel().getColumn(4).setPreferredWidth(320);
            javax.swing.table.TableRowSorter<javax.swing.table.DefaultTableModel> vsort =
                    new javax.swing.table.TableRowSorter<>(validationModel);
            valTable.setRowSorter(vsort);
            validationModel.addTableModelListener(ev -> {
                if (ev.getColumn() != 0) return;
                int row = ev.getFirstRow();
                if (row < 0 || row >= validationCatalog.size()) return;
                String id = validationCatalog.get(row).id();
                if (Boolean.TRUE.equals(validationModel.getValueAt(row, 0))) validationEnabledIds.add(id);
                else validationEnabledIds.remove(id);
            });

            JComboBox<String> provCombo = new JComboBox<>();
            provCombo.addItem("All providers");
            for (String prov : ValidationCatalog.byProvider().keySet()) provCombo.addItem(prov);
            JTextField vsearch = new JTextField(16);
            JButton selShown   = new JButton("Select shown");
            JButton deselShown = new JButton("Deselect shown");
            liveValidateBox = new ToggleSwitch("Allow live (network) validation", settings.isLiveValidationEnabled());
            liveValidateBox.setToolTipText("Off by default. When ON, selected \"Live (network)\" providers are checked by "
                    + "sending the found key to the provider's verify endpoint (one read-only request). Only enable against "
                    + "providers/apps you are authorized to test.");
            JPanel vcontrols = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            vcontrols.add(new JLabel("Provider:")); vcontrols.add(provCombo);
            vcontrols.add(new JLabel("  Search:")); vcontrols.add(vsearch);
            vcontrols.add(selShown); vcontrols.add(deselShown);
            vcontrols.add(new JLabel("   ")); vcontrols.add(liveValidateBox);

            Runnable applyVFilter = () -> {
                String prov = (String) provCombo.getSelectedItem();
                String q = vsearch.getText().trim().toLowerCase();
                vsort.setRowFilter(new javax.swing.RowFilter<javax.swing.table.DefaultTableModel, Integer>() {
                    @Override public boolean include(Entry<? extends javax.swing.table.DefaultTableModel, ? extends Integer> e) {
                        boolean provOk = prov == null || prov.equals("All providers") || prov.equals(String.valueOf(e.getValue(2)));
                        boolean qOk = q.isEmpty() || String.valueOf(e.getValue(1)).toLowerCase().contains(q);
                        return provOk && qOk;
                    }
                });
            };
            provCombo.addActionListener(e -> applyVFilter.run());
            vsearch.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                public void insertUpdate(javax.swing.event.DocumentEvent e) { applyVFilter.run(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { applyVFilter.run(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { applyVFilter.run(); }
            });
            selShown.addActionListener(e -> { for (int v = 0; v < valTable.getRowCount(); v++)
                    validationModel.setValueAt(Boolean.TRUE, valTable.convertRowIndexToModel(v), 0); });
            deselShown.addActionListener(e -> { for (int v = 0; v < valTable.getRowCount(); v++)
                    validationModel.setValueAt(Boolean.FALSE, valTable.convertRowIndexToModel(v), 0); });

            JPanel vnorth = new JPanel(new BorderLayout(0, 4));
            vnorth.add(intro, BorderLayout.NORTH);
            vnorth.add(vcontrols, BorderLayout.SOUTH);
            valTab.add(vnorth, BorderLayout.NORTH);
            valTab.add(new JScrollPane(valTable), BorderLayout.CENTER);

            validationCustomArea = new JTextArea(String.join("\n", settings.getValidationCustomRules()), 4, 20);
            validationCustomArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            validationCustomArea.setToolTipText("One per line: name | regex | STATE | note   "
                    + "(STATE = ACTIVE, INACTIVE, RESTRICTED or UNKNOWN). "
                    + "Example:  sandbox key | ^sk_test_ | INACTIVE | our test key");
            JPanel vcustom = new JPanel(new BorderLayout(4, 2));
            vcustom.setBorder(new javax.swing.border.TitledBorder(
                    "Custom validation rules  (name | regex | STATE | note — matched against each finding's value)"));
            vcustom.add(new JScrollPane(validationCustomArea), BorderLayout.CENTER);

            validationBaseUrlArea = new JTextArea(String.join("\n", settings.getValidationBaseUrls()), 4, 20);
            validationBaseUrlArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            validationBaseUrlArea.setToolTipText("Set or override the endpoint a live check uses, one per line. "
                    + "Provider name must match the table. Self-hosted: GitLab = https://gitlab.yourco.com   "
                    + "Full endpoint: Z.ai = GET https://api.z.ai/v1/me");
            JPanel vbase = new JPanel(new BorderLayout(4, 2));
            vbase.setBorder(new javax.swing.border.TitledBorder(
                    "Validation endpoints  (Provider = https://your-host, or Provider = GET https://host/path)"));
            vbase.add(new JScrollPane(validationBaseUrlArea), BorderLayout.CENTER);

            JPanel vsouth = new JPanel(new java.awt.GridLayout(1, 2, 6, 0));
            vsouth.add(vcustom);
            vsouth.add(vbase);
            vsouth.setPreferredSize(new Dimension(10, 130));
            valTab.add(vsouth, BorderLayout.SOUTH);

            subTabs.addTab("Validation", valTab);
        }

        // ═════════════════════════════════════════════════════════════════════
        // TAB 3 — AI / MCP
        // ═════════════════════════════════════════════════════════════════════
        JPanel mcpTab = new JPanel(new BorderLayout(8, 6));
        mcpTab.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));

        // ── Top row: enable toggle + port + apply + status ────────────────
        JPanel mcpTopRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        boolean mcpRunning = mcpServer.isRunning();
        mcpEnabledBox = new ToggleSwitch("Enable MCP Server", mcpRunning);
        mcpEnabledBox.setToolTipText(
                "Starts a local JSON-RPC server so Claude and other AI tools can start scans, " +
                "read findings, and export reports programmatically via the MCP protocol. " +
                "Server binds to localhost only; a random auth token is required on every request.");
        mcpTopRow.add(mcpEnabledBox);

        mcpTopRow.add(new JLabel("   Port:"));
        mcpPortSpinner = new JSpinner(new SpinnerNumberModel(mcpServer.getPort(), 1024, 65535, 1));
        mcpPortSpinner.setEditor(new JSpinner.NumberEditor(mcpPortSpinner, "#"));
        mcpPortSpinner.setPreferredSize(new Dimension(72, 24));
        mcpTopRow.add(mcpPortSpinner);

        JButton applyMcpBtn = new JButton("Apply");
        applyMcpBtn.setToolTipText("Start or stop the MCP server with the current port settings");
        applyMcpBtn.addActionListener(e -> onApplyMcp());
        mcpTopRow.add(applyMcpBtn);

        mcpStatusLabel = new JLabel(mcpRunning ? "● Running on :" + mcpServer.getPort() : "○ Stopped");
        mcpStatusLabel.setForeground(mcpRunning ? new Color(0, 160, 0) : Color.GRAY);
        mcpTopRow.add(mcpStatusLabel);

        // ── AI Provider API Key row ──────────────────────────────────────────
        // Lets users plug in their own Anthropic / OpenAI / etc. key for outbound
        // AI calls (triage, summarisation, etc.).  Stored in the same encrypted-at-
        // rest Java prefs store as the MCP token.  Default-masked; toggle reveals.
        // Row 1: provider + API key (drives the "AI Triage All" button on the Scan tab)
        JPanel aiKeyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        aiKeyRow.add(new JLabel("AI Triage — Provider:"));
        final String[] AI_LABELS = {"Claude via MCP (no key)", "Claude (Anthropic)", "OpenAI", "Google Gemini", "DeepSeek", "OpenAI-compatible (custom endpoint)"};
        final AiTriageProvider.Provider[] AI_PROVIDERS = {
                AiTriageProvider.Provider.MCP,
                AiTriageProvider.Provider.ANTHROPIC, AiTriageProvider.Provider.OPENAI,
                AiTriageProvider.Provider.GEMINI, AiTriageProvider.Provider.DEEPSEEK,
                AiTriageProvider.Provider.OPENAI_COMPATIBLE };
        final JComboBox<String> aiProviderCombo = new JComboBox<>(AI_LABELS);
        for (int i = 0; i < AI_PROVIDERS.length; i++) if (AI_PROVIDERS[i] == settings.getAiProvider()) aiProviderCombo.setSelectedIndex(i);
        // Apply (and persist) the provider the moment it's picked — no separate save step needed.
        // Previously the choice only took effect via the "Save AI Settings" button, which was easy
        // to miss (users clicked the bottom "Save Settings" and the provider never applied).
        aiProviderCombo.addActionListener(ev -> {
            settings.setAiProvider(AI_PROVIDERS[Math.max(0, aiProviderCombo.getSelectedIndex())]);
            settings.saveToPrefs(prefs);
        });
        aiProviderCombo.setToolTipText("<html>Backend used by 'AI Triage All' on the Scan tab.<br>"
                + "<b>Claude via MCP (no key)</b> uses a connected Claude client (Claude Code / Desktop) over the<br>"
                + "MCP server above — no API key needed. The other providers call their API directly and need a key.</html>");
        aiKeyRow.add(aiProviderCombo);

        aiKeyRow.add(new JLabel("   API Key:"));
        String savedAiKey = settings.getAiApiKey() != null && !settings.getAiApiKey().isBlank()
                ? settings.getAiApiKey() : prefs.getString("ai.provider.key");
        aiKeyField = new JPasswordField(savedAiKey == null ? "" : savedAiKey, 32);
        aiKeyField.setEchoChar('•');
        aiKeyField.setToolTipText(
                "<html>API key for the selected provider. Stored locally in user prefs;<br>" +
                "sent only to that provider when you run AI Triage. Secret values in<br>" +
                "findings are redacted before they are sent.</html>");
        aiKeyRow.add(aiKeyField);

        showAiKeyBtn = new JToggleButton("Show");
        showAiKeyBtn.setToolTipText("Show / hide key");
        showAiKeyBtn.setMargin(new Insets(0, 6, 0, 6));
        showAiKeyBtn.setPreferredSize(new Dimension(60, 24));
        showAiKeyBtn.addActionListener(e -> {
            boolean visible = showAiKeyBtn.isSelected();
            aiKeyField.setEchoChar(visible ? (char) 0 : '•');
            showAiKeyBtn.setText(visible ? "Hide" : "Show");
        });
        aiKeyRow.add(showAiKeyBtn);

        // Row 2: model + custom endpoint + save
        JPanel aiModelRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        aiModelRow.add(new JLabel("Model:"));
        final JTextField aiModelField = new JTextField(settings.getAiModel(), 18);
        aiModelField.setToolTipText("Leave blank or 'latest' to auto-pick the newest flagship model for the provider.");
        aiModelRow.add(aiModelField);
        aiModelRow.add(new JLabel("   Endpoint (OpenAI-compatible only):"));
        final JTextField aiEndpointField = new JTextField(settings.getAiEndpoint(), 26);
        aiEndpointField.setToolTipText("Custom https:// chat-completions URL for the 'OpenAI-compatible' provider (or a local http://localhost model).");
        aiModelRow.add(aiEndpointField);

        JButton saveAiKeyBtn = new JButton("Save AI Settings");
        saveAiKeyBtn.setToolTipText("Persist the AI provider, key, model, and endpoint.");
        saveAiKeyBtn.addActionListener(e -> {
            settings.setAiProvider(AI_PROVIDERS[Math.max(0, aiProviderCombo.getSelectedIndex())]);
            String k = new String(aiKeyField.getPassword()).trim();
            settings.setAiApiKey(k);
            settings.setAiModel(aiModelField.getText().trim());
            settings.setAiEndpoint(aiEndpointField.getText().trim());
            settings.saveToPrefs(prefs);
            prefs.setString("ai.provider.key", k);   // back-compat with the earlier pref key
            statusLabel.setText("AI triage settings saved.");
            statusLabel.setForeground(new Color(0, 160, 0));
        });
        aiModelRow.add(saveAiKeyBtn);

        // Stack mcpTopRow + the two AI rows as the NORTH region
        JPanel mcpNorth = new JPanel();
        mcpNorth.setLayout(new BoxLayout(mcpNorth, BoxLayout.Y_AXIS));
        mcpTopRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        aiKeyRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        aiModelRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        mcpNorth.add(mcpTopRow);
        mcpNorth.add(aiKeyRow);
        mcpNorth.add(aiModelRow);
        mcpTab.add(mcpNorth, BorderLayout.NORTH);

        // ── Left panel: JSON config snippet + action buttons ──────────────
        mcpConfigArea = new JTextArea(buildMcpConfigJson(), 12, 40);
        mcpConfigArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        mcpConfigArea.setEditable(false);
        mcpConfigArea.setToolTipText(
                "Claude Desktop: paste into %APPDATA%\\Claude\\claude_desktop_config.json and restart.");

        JPanel configPanel = new JPanel(new BorderLayout(4, 4));
        configPanel.setBorder(new TitledBorder("Config Snippet"));
        configPanel.add(new JScrollPane(mcpConfigArea), BorderLayout.CENTER);

        JPanel configBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton copyJsonBtn    = new JButton("Copy JSON");
        JButton copyCliBtn     = new JButton("Copy CLI Command");
        JButton saveSnippetBtn = new JButton("Save to file\u2026");
        JButton regenBtn       = new JButton("Regenerate Token");
        copyJsonBtn.setToolTipText("Claude Desktop: copies the mcpServers JSON block to paste into claude_desktop_config.json");
        copyCliBtn.setToolTipText("Claude Code CLI: copies the 'claude mcp add' command — run it once in your terminal");
        saveSnippetBtn.setToolTipText("Save the JSON config snippet as a .json file");
        regenBtn.setToolTipText("Generate a new auth token. Update your Claude config after regenerating.");
        copyJsonBtn.addActionListener(e    -> onCopyJson());
        copyCliBtn.addActionListener(e     -> onCopyCliCommand());
        saveSnippetBtn.addActionListener(e -> onSaveSnippet());
        regenBtn.addActionListener(e       -> onRegenToken());
        configBtnBar.add(copyJsonBtn);
        configBtnBar.add(copyCliBtn);
        configBtnBar.add(saveSnippetBtn);
        configBtnBar.add(regenBtn);
        configPanel.add(configBtnBar, BorderLayout.SOUTH);

        // ── Right panel: setup notes + token display + download button ────
        JTextArea setupNotesArea = new JTextArea(buildSetupNotes());
        setupNotesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        setupNotesArea.setEditable(false);
        setupNotesArea.setLineWrap(true);
        setupNotesArea.setWrapStyleWord(true);

        JPanel notesPanel = new JPanel(new BorderLayout(4, 4));
        notesPanel.setBorder(new TitledBorder("Setup & Troubleshooting Notes"));

        JScrollPane notesScroll = new JScrollPane(setupNotesArea);
        notesScroll.getVerticalScrollBar().setUnitIncrement(16);

        JPanel tokenRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        tokenRow.add(new JLabel("Token:"));
        mcpTokenLabel = new JLabel(mcpServer.getToken());
        mcpTokenLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        mcpTokenLabel.setForeground(mcpRunning ? new Color(0, 110, 0) : Color.GRAY);
        tokenRow.add(mcpTokenLabel);

        notesPanel.add(tokenRow, BorderLayout.NORTH);
        notesPanel.add(notesScroll, BorderLayout.CENTER);

        JPanel notesBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton downloadNotesBtn = new JButton("Download Setup Guide\u2026");
        downloadNotesBtn.setToolTipText("Save the AI setup & triage guide");
        downloadNotesBtn.addActionListener(e -> onDownloadSetupGuide());
        notesBtnBar.add(downloadNotesBtn);
        notesPanel.add(notesBtnBar, BorderLayout.SOUTH);

        // ── Split: config (left, 50%) | notes (right, 50%) ────────────────
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, configPanel, notesPanel);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerSize(6);
        splitPane.setOneTouchExpandable(true);
        splitPane.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                splitPane.removeComponentListener(this);
                SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
            }
        });
        mcpTab.add(splitPane, BorderLayout.CENTER);

        subTabs.addTab("AI / MCP", mcpTab);

        // ═════════════════════════════════════════════════════════════════════
        // TAB 4 — Proxy (live MITM proxy controls)
        // ═════════════════════════════════════════════════════════════════════
        if (proxyTabContent != null) {
            subTabs.addTab("Proxy", proxyTabContent);
        }

        rootPanel.add(subTabs, BorderLayout.CENTER);

        // ── Save/Reset — always visible below the sub-tabs ────────────────
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

        wireAutoSave();
    }

    // =========================================================================
    // Actions
    // =========================================================================

    private void onSave() {
        settings.setEnabled(enabledBox.isSelected());
        settings.setTier(ScanSettings.ScanTier.valueOf((String) tierCombo.getSelectedItem()));
        settings.setEntropyThreshold(((Number) entropySpinner.getValue()).doubleValue());
        settings.setPiiEnabled(piiBox.isSelected());
        settings.setScanRequestsEnabled(scanRequestsBox.isSelected());
        settings.setLiveValidationEnabled(liveValidateBox.isSelected());

        // Validation sub-tab: selected catalog ids + custom rules + endpoint overrides
        if (validationModel != null) {
            settings.setValidationEnabledIds(validationEnabledIds);
            java.util.List<String> vlines = new java.util.ArrayList<>();
            for (String l : validationCustomArea.getText().split("\n")) if (!l.isBlank()) vlines.add(l.trim());
            settings.setValidationCustomRules(vlines);
            java.util.List<String> blines = new java.util.ArrayList<>();
            for (String l : validationBaseUrlArea.getText().split("\n")) if (!l.isBlank()) blines.add(l.trim());
            settings.setValidationBaseUrls(blines);
        }

        List<String> cdn = new ArrayList<>();
        for (String line : cdnArea.getText().split("\n")) { String t = line.trim(); if (!t.isEmpty()) cdn.add(t); }
        settings.setCdnBlocklist(cdn);

        List<String> keyBlock = new ArrayList<>();
        for (String line : keyBlocklistArea.getText().split("\n")) { String t = line.trim(); if (!t.isEmpty()) keyBlock.add(t); }
        settings.setKeyBlocklist(keyBlock);

        List<String> keyAllow = new ArrayList<>();
        for (String line : keyAllowlistArea.getText().split("\n")) { String t = line.trim(); if (!t.isEmpty()) keyAllow.add(t); }
        settings.setKeyAllowlist(keyAllow);

        settings.setPlaywrightEnabled(pwEnabledBox.isSelected());
        settings.setPlaywrightMaxPages(((Number) maxPagesSpinner.getValue()).intValue());
        settings.setBrowserPath(browserPathField.getText().trim());

        List<String> customRules = new ArrayList<>();
        for (String line : customRulesArea.getText().split("\n")) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#")) customRules.add(t);
        }
        settings.setCustomRules(customRules);
        settings.setCustomRulesEnabled(customRulesEnabledBox.isSelected());
        settings.setCustomRulesOnly(customRulesOnlyBox.isSelected());

        int tidx = urlTimeoutCombo.getSelectedIndex();
        if (tidx >= 0 && tidx < URL_TIMEOUT_SECONDS.length)
            settings.setUrlTimeoutSeconds(URL_TIMEOUT_SECONDS[tidx]);

        settings.saveToPrefs(prefs);
        prefs.flush();

        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        statusLabel.setText("Saved at " + time + "   [tier=" + settings.getTier() +
                "  entropy=" + String.format("%.1f", settings.getEntropyThreshold()) +
                "  pii=" + settings.isPiiEnabled() + "]");
        statusLabel.setForeground(new Color(0, 130, 0));
    }

    private void onReset() {
        int confirm = JOptionPane.showConfirmDialog(rootPanel,
                "Reset all settings to defaults?", "Confirm Reset",
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;
        settings.resetToDefaults();
        settings.saveToPrefs(prefs);
        prefs.flush();
        syncControlsFromSettings();
        statusLabel.setText("Reset to defaults.");
        statusLabel.setForeground(Color.GRAY);
    }

    public void loadFromPrefs() {
        settings.loadFromPrefs(prefs);
        if (SwingUtilities.isEventDispatchThread()) {
            syncControlsFromSettings();
        } else {
            SwingUtilities.invokeLater(this::syncControlsFromSettings);
        }
    }

    private void syncControlsFromSettings() {
        if (enabledBox        != null) enabledBox.setSelected(settings.isEnabled());
        if (tierCombo         != null) tierCombo.setSelectedItem(settings.getTier().name());
        if (entropySpinner    != null) entropySpinner.setValue(settings.getEntropyThreshold());
        if (piiBox            != null) piiBox.setSelected(settings.isPiiEnabled());
        if (scanRequestsBox   != null) scanRequestsBox.setSelected(settings.isScanRequestsEnabled());
        if (liveValidateBox   != null) liveValidateBox.setSelected(settings.isLiveValidationEnabled());
        if (cdnArea           != null) cdnArea.setText(String.join("\n", settings.getCdnBlocklist()));
        if (keyBlocklistArea  != null) keyBlocklistArea.setText(String.join("\n", settings.getKeyBlocklist()));
        if (keyAllowlistArea  != null) keyAllowlistArea.setText(String.join("\n", settings.getKeyAllowlist()));
        if (pwEnabledBox      != null) pwEnabledBox.setSelected(settings.isPlaywrightEnabled());
        if (maxPagesSpinner   != null) maxPagesSpinner.setValue(settings.getPlaywrightMaxPages());
        if (browserPathField  != null) browserPathField.setText(settings.getBrowserPath());
        if (mcpEnabledBox     != null) mcpEnabledBox.setSelected(mcpServer.isRunning());
        if (mcpPortSpinner    != null) mcpPortSpinner.setValue(mcpServer.getPort());
        if (mcpTokenLabel     != null) {
            mcpTokenLabel.setText(mcpServer.getToken());
            mcpTokenLabel.setForeground(mcpServer.isRunning() ? new Color(0, 110, 0) : Color.GRAY);
        }
        if (mcpConfigArea     != null) mcpConfigArea.setText(buildMcpConfigJson());
        if (customRulesArea   != null) {
            List<String> rules = settings.getCustomRules();
            customRulesArea.setText(rules.isEmpty() ? CUSTOM_RULES_PLACEHOLDER : String.join("\n", rules));
        }
        if (customRulesEnabledBox != null) customRulesEnabledBox.setSelected(settings.isCustomRulesEnabled());
        if (customRulesOnlyBox    != null) customRulesOnlyBox.setSelected(settings.isCustomRulesOnly());
        if (urlTimeoutCombo   != null) {
            int cur = settings.getUrlTimeoutSeconds();
            for (int i = 0; i < URL_TIMEOUT_SECONDS.length; i++) {
                if (URL_TIMEOUT_SECONDS[i] == cur) { urlTimeoutCombo.setSelectedIndex(i); break; }
            }
        }
        if (statusLabel       != null) statusLabel.setText("Settings loaded.");
    }

    // ── MCP actions ───────────────────────────────────────────────────────────

    private void onApplyMcp() {
        int newPort  = ((Number) mcpPortSpinner.getValue()).intValue();
        boolean enable = mcpEnabledBox.isSelected();

        mcpServer.setPort(newPort);
        prefs.setString("mcp.port",    String.valueOf(newPort));
        prefs.setBoolean("mcp.enabled", enable);

        if (enable) {
            try {
                mcpServer.restart();
                mcpStatusLabel.setText("● Running on :" + newPort);
                mcpStatusLabel.setForeground(new Color(0, 160, 0));
                mcpTokenLabel.setForeground(new Color(0, 110, 0));
                mcpConfigArea.setText(buildMcpConfigJson());
            } catch (IOException ex) {
                mcpStatusLabel.setText("\u2717 Failed: " + ex.getMessage());
                mcpStatusLabel.setForeground(Color.RED);
            }
        } else {
            mcpServer.stop();
            mcpStatusLabel.setText("○ Stopped");
            mcpStatusLabel.setForeground(Color.GRAY);
            mcpTokenLabel.setForeground(Color.GRAY);
        }
    }

    private void onRegenToken() {
        String newToken = UUID.randomUUID().toString().replace("-", "");
        mcpServer.setToken(newToken);
        prefs.setString("mcp.token", newToken);
        mcpTokenLabel.setText(newToken);
        mcpTokenLabel.setForeground(new Color(0, 110, 0));
        mcpConfigArea.setText(buildMcpConfigJson());
        if (mcpServer.isRunning()) {
            try { mcpServer.restart(); } catch (IOException ex) {
                mcpStatusLabel.setText("\u2717 Restart failed: " + ex.getMessage());
                mcpStatusLabel.setForeground(Color.RED);
            }
        }
        JOptionPane.showMessageDialog(rootPanel,
                "New token generated.\nRe-copy the config and restart Claude.",
                "Token Regenerated", JOptionPane.INFORMATION_MESSAGE);
    }

    private void onCopyJson() {
        if (!mcpServer.isRunning()) {
            int choice = JOptionPane.showConfirmDialog(rootPanel,
                    "<html><b>MCP server is not running.</b><br><br>" +
                    "The config you are about to copy will not work until the MCP server is started.<br><br>" +
                    "Would you like to start it now?</html>",
                    "MCP Not Running", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.CANCEL_OPTION) return;
            if (choice == JOptionPane.YES_OPTION) {
                mcpEnabledBox.setSelected(true);
                onApplyMcp();
                if (!mcpServer.isRunning()) {
                    JOptionPane.showMessageDialog(rootPanel,
                            "<html><b>Failed to start MCP server.</b><br><br>" +
                            "Check that port " + ((Number) mcpPortSpinner.getValue()).intValue() + " is not already in use.</html>",
                            "Start Failed", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
               .setContents(new StringSelection(mcpConfigArea.getText()), null);
        statusLabel.setText("MCP config JSON copied to clipboard.");
        statusLabel.setForeground(new Color(0, 130, 0));
        JOptionPane.showMessageDialog(rootPanel,
                "<html><b>Config copied to clipboard!</b><br><br>" +
                "Paste it into Claude Desktop's config file:<br>" +
                "<code>%APPDATA%\\Claude\\claude_desktop_config.json</code><br><br>" +
                "If the file already exists, merge the <code>\"secretsifter-desktop\"</code> entry<br>" +
                "into the existing <code>\"mcpServers\"</code> block.<br><br>" +
                "<i>Note: the Burp extension uses the key <code>\"secretsifter\"</code> — both can coexist.</i><br><br>" +
                "Then restart Claude Desktop.</html>",
                "Claude Config", JOptionPane.INFORMATION_MESSAGE);
    }

    private void onCopyCliCommand() {
        if (!mcpServer.isRunning()) {
            statusLabel.setText("Enable MCP server first to get the CLI command.");
            statusLabel.setForeground(Color.ORANGE.darker());
            return;
        }
        String cmd = "claude mcp add --transport http secretsifter-desktop " +
                "http://localhost:" + mcpServer.getPort() + "/mcp " +
                "--header \"Authorization: Bearer " + mcpServer.getToken() + "\"";
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(cmd), null);
        statusLabel.setText("Claude Code CLI command copied — paste into terminal and run once.");
        statusLabel.setForeground(new Color(0, 110, 0));
    }

    private void onSaveSnippet() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save MCP Config Snippet");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new java.io.File(System.getProperty("user.home"), "secretsifter-desktop-mcp.json"));
        if (chooser.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        java.io.File f = chooser.getSelectedFile();
        if (!f.getName().toLowerCase().endsWith(".json")) f = new java.io.File(f.getAbsolutePath() + ".json");
        try (OutputStreamWriter fw = new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8)) {
            fw.write(mcpConfigArea.getText());
            statusLabel.setText("MCP config saved to " + f.getAbsolutePath());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel, "Failed to save: " + ex.getMessage(), "Save Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onDownloadSetupGuide() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save Setup Guide");
        fc.setFileFilter(new FileNameExtensionFilter("Markdown files (*.md)", "md"));
        fc.setSelectedFile(new java.io.File(System.getProperty("user.home"), "SecretSifter_AI_Setup_Guide.md"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        java.io.File dest = fc.getSelectedFile();
        if (!dest.getName().toLowerCase().endsWith(".md")) dest = new java.io.File(dest.getAbsolutePath() + ".md");
        try (OutputStreamWriter fw = new OutputStreamWriter(new FileOutputStream(dest), StandardCharsets.UTF_8)) {
            fw.write(buildSetupGuideMarkdown());
            int open = JOptionPane.showConfirmDialog(rootPanel,
                    "Setup guide saved to:\n" + dest.getAbsolutePath() + "\n\nOpen it now?",
                    "Setup Guide Downloaded", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
            if (open == JOptionPane.YES_OPTION) {
                try { Desktop.getDesktop().open(dest); } catch (Exception ignored) {}
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save setup guide: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String buildSetupGuideMarkdown() {
        int    port = mcpServer.getPort();
        String tok  = mcpServer.getToken();
        return
"# SecretSifter Desktop — AI / MCP & REST API Setup Guide\n\n" +
"**Version:** 1.8.3  \n" +
"**Transport:** HTTP (JSON-RPC 2.0)  \n" +
"**Protocol:** MCP 2025-06-18  \n\n" +
"---\n\n" +
"## Quick Start\n\n" +
"1. In SecretSifter → **Settings → AI / MCP**, enable the MCP server and click **Apply**.\n" +
"2. Note the port (default **" + port + "**) and your Bearer token shown in the Token field.\n" +
"3. Follow the setup steps for your AI client below.\n\n" +
"---\n\n" +
"## Claude Code (CLI)\n\n" +
"Run once in your terminal:\n\n" +
"```bash\n" +
"claude mcp add --transport http secretsifter-desktop \\\n" +
"  http://localhost:" + port + "/mcp \\\n" +
"  --header \"Authorization: Bearer " + tok + "\"\n" +
"```\n\n" +
"**PowerShell:**\n" +
"```powershell\n" +
"claude mcp add --transport http secretsifter-desktop `\n" +
"  http://localhost:" + port + "/mcp `\n" +
"  --header \"Authorization: Bearer " + tok + "\"\n" +
"```\n\n" +
"Verify: `claude mcp list` → should show `secretsifter-desktop: ✓ Connected`\n\n" +
"---\n\n" +
"## Claude Desktop\n\n" +
"1. Click **Copy JSON** in SecretSifter Settings.\n" +
"2. Open `%APPDATA%\\Claude\\claude_desktop_config.json`.\n" +
"3. Merge the `\"secretsifter-desktop\"` entry into the `\"mcpServers\"` block:\n\n" +
"```json\n" +
"{\n" +
"  \"mcpServers\": {\n" +
"    \"secretsifter-desktop\": {\n" +
"      \"type\": \"http\",\n" +
"      \"url\": \"http://localhost:" + port + "/mcp\",\n" +
"      \"headers\": {\n" +
"        \"Authorization\": \"Bearer " + tok + "\"\n" +
"      }\n" +
"    }\n" +
"  }\n" +
"}\n" +
"```\n\n" +
"> **Note:** If you also use the Burp SecretSifter extension, it registers as `\"secretsifter\"` — both keys coexist in the same config file.\n\n" +
"4. Restart Claude Desktop.\n\n" +
"---\n\n" +
"## REST API — Automated Scripting\n\n" +
"All REST endpoints share the same Bearer token. Base URL: `http://localhost:" + port + "`\n\n" +
"| Method | Path | Description |\n" +
"|--------|------|-------------|\n" +
"| POST | `/api/scan` | Start a scan |\n" +
"| GET | `/api/scan/status` | Poll scan progress |\n" +
"| DELETE | `/api/scan` | Cancel running scan |\n" +
"| GET | `/api/findings` | Get all findings |\n" +
"| DELETE | `/api/findings` | Clear all findings |\n" +
"| PATCH | `/api/findings/{n}` | Update finding severity |\n" +
"| DELETE | `/api/findings/{n}` | Delete one finding |\n" +
"| POST | `/api/report` | Export CSV / JSON / HTML report |\n" +
"| GET | `/api/settings` | Read scanner settings |\n" +
"| PATCH | `/api/settings` | Update scanner settings |\n" +
"| GET | `/api/targets` | Per-target scan outcomes |\n" +
"| GET | `/api/rules` | Get custom rules |\n" +
"| PUT | `/api/rules` | Replace all custom rules |\n" +
"| POST | `/api/rules` | Add one custom rule |\n" +
"| GET | `/api/logs` | Read log buffer |\n" +
"| DELETE | `/api/logs` | Clear log buffer |\n\n" +
"### curl Examples\n\n" +
"```bash\n" +
"TOKEN=" + tok + "\n" +
"BASE=http://localhost:" + port + "\n\n" +
"# Start a scan\n" +
"curl -s -X POST $BASE/api/scan \\\n" +
"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
"  -H \"Content-Type: application/json\" \\\n" +
"  -d '{\"urls\":[\"https://example.com\"],\"tier\":\"FULL\",\"headless\":false,\"threads\":10}'\n\n" +
"# Poll status\n" +
"curl -s $BASE/api/scan/status -H \"Authorization: Bearer $TOKEN\"\n\n" +
"# Get findings\n" +
"curl -s $BASE/api/findings -H \"Authorization: Bearer $TOKEN\"\n\n" +
"# Export HTML report\n" +
"curl -s -X POST $BASE/api/report \\\n" +
"  -H \"Authorization: Bearer $TOKEN\" \\\n" +
"  -H \"Content-Type: application/json\" \\\n" +
"  -d '{\"format\":\"html\",\"path\":\"C:/Reports/findings.html\"}'\n" +
"```\n\n" +
"### Python Example\n\n" +
"```python\n" +
"import requests, time\n\n" +
"BASE  = \"http://localhost:" + port + "\"\n" +
"TOKEN = \"" + tok + "\"\n" +
"AUTH  = {\"Authorization\": f\"Bearer {TOKEN}\"}\n\n" +
"# Start scan\n" +
"r = requests.post(f\"{BASE}/api/scan\", json={\n" +
"    \"urls\": [\"https://target.example.com\"],\n" +
"    \"tier\": \"FULL\", \"headless\": False, \"threads\": 10\n" +
"}, headers=AUTH)\n" +
"print(r.json())\n\n" +
"# Poll until done\n" +
"while True:\n" +
"    s = requests.get(f\"{BASE}/api/scan/status\", headers=AUTH).json()\n" +
"    print(s[\"status\"], s.get(\"progress\", \"\"))\n" +
"    if s[\"status\"] in (\"idle\", \"done\", \"stopped\"): break\n" +
"    time.sleep(3)\n\n" +
"# Fetch findings\n" +
"findings = requests.get(f\"{BASE}/api/findings\", headers=AUTH).json()\n" +
"print(f\"Found {len(findings)} secrets\")\n" +
"```\n\n" +
"---\n\n" +
"## MCP Tools Reference\n\n" +
"All tools are prefixed `secretsifter_`. Key tools:\n\n" +
"| Tool | Description |\n" +
"|------|-------------|\n" +
"| `secretsifter_start_bulk_scan` | Start scan with URL list |\n" +
"| `secretsifter_get_scan_status` | Poll scan progress |\n" +
"| `secretsifter_cancel_scan` | Stop running scan |\n" +
"| `secretsifter_get_findings` | Get all findings |\n" +
"| `secretsifter_get_summary` | Count + severity breakdown |\n" +
"| `secretsifter_update_finding_severity` | Change HIGH/MEDIUM/LOW/INFO |\n" +
"| `secretsifter_delete_finding` | Remove one finding by index |\n" +
"| `secretsifter_bulk_delete_findings` | Remove multiple findings |\n" +
"| `secretsifter_export_report` | Save CSV / JSON / HTML / ZIP |\n" +
"| `secretsifter_get_settings` | Read scanner config |\n" +
"| `secretsifter_update_settings` | Change tier, entropy, etc. |\n" +
"| `secretsifter_get_custom_rules` | List custom rules |\n" +
"| `secretsifter_add_custom_rule` | Add one rule (validates regex) |\n" +
"| `secretsifter_set_custom_rules` | Replace all custom rules |\n" +
"| `secretsifter_scan_har_file` | Scan a .har file |\n" +
"| `secretsifter_get_logs` | Read log buffer |\n" +
"| `secretsifter_clear_logs` | Clear log buffer |\n\n" +
"---\n\n" +
"## Troubleshooting\n\n" +
"**\"Failed to connect\"**\n" +
"- Is the MCP server toggle **enabled** and **Applied**?\n" +
"- Did you restart Claude after running `claude mcp add`?\n" +
"- Token mismatch? Remove and re-register:\n" +
"  ```\n" +
"  claude mcp remove secretsifter-desktop\n" +
"  # click 'Copy CLI Command' and re-run\n" +
"  ```\n\n" +
"**Port conflict**\n" +
"```\n" +
"netstat -ano | findstr " + port + "\n" +
"```\n\n" +
"**Test with curl**\n" +
"```bash\n" +
"curl -s -X POST http://localhost:" + port + "/mcp \\\n" +
"  -H \"Content-Type: application/json\" \\\n" +
"  -H \"Authorization: Bearer " + tok + "\" \\\n" +
"  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}'\n" +
"```\n" +
"Expected: `{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{...}}`\n\n" +
"---\n\n" +
"## Token Lifecycle\n\n" +
"- Token persists across app restarts (stored in Java Preferences).\n" +
"- Re-register Claude **only** when you click **Regenerate Token**.\n" +
"- Server binds to `localhost` only — not reachable from the network.\n";
    }

    private void onImportCustomRules() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import custom rules");
        fc.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        if (fc.showOpenDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                new FileInputStream(fc.getSelectedFile()), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder(customRulesArea.getText());
            String line; int count = 0;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (!t.isEmpty()) { sb.append("\n").append(t); count++; }
            }
            customRulesArea.setText(sb.toString().trim());
            statusLabel.setText("Imported " + count + " line(s) from " + fc.getSelectedFile().getName());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel, "Import failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onExportCustomRules() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export custom rules");
        fc.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        fc.setSelectedFile(new java.io.File("custom-rules.txt"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        java.io.File out = fc.getSelectedFile();
        if (!out.getName().toLowerCase().endsWith(".txt")) out = new java.io.File(out.getParentFile(), out.getName() + ".txt");
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
            pw.print(customRulesArea.getText());
            statusLabel.setText("Exported to " + out.getName());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showInstallInstructions() {
        String jarPath = "secretsifter.jar";
        try {
            java.net.URL loc = getClass().getProtectionDomain().getCodeSource().getLocation();
            if (loc != null) jarPath = new java.io.File(loc.toURI()).getAbsolutePath();
        } catch (Exception ignored) {}
        JOptionPane.showMessageDialog(rootPanel,
                "Browser Mode — Setup\n\n" +
                "Windows 10 / 11:\n" +
                "  No setup required. SecretSifter automatically uses Microsoft Edge,\n" +
                "  which is pre-installed on all modern Windows machines.\n\n" +
                "If Edge is not found, Chromium is downloaded automatically the first time\n" +
                "Browser Mode is used (~120 MB, one-time).\n\n" +
                "Manual Chromium install (optional):\n" +
                "  java -cp \"" + jarPath + "\" com.microsoft.playwright.CLI install chromium",
                "Browser Mode Setup", JOptionPane.INFORMATION_MESSAGE);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private String buildMcpConfigJson() {
        int port = mcpServer.getPort();
        String tok = mcpServer.getToken();
        return "{\n" +
               "  \"mcpServers\": {\n" +
               "    \"secretsifter-desktop\": {\n" +
               "      \"type\": \"http\",\n" +
               "      \"url\": \"http://localhost:" + port + "/mcp\",\n" +
               "      \"headers\": {\n" +
               "        \"Authorization\": \"Bearer " + tok + "\"\n" +
               "      }\n" +
               "    }\n" +
               "  }\n" +
               "}";
    }

    private static String buildSetupNotes() {
        return
"═══════════════════════════════════════════════════════════════\n" +
"  SecretSifter Desktop  —  AI / MCP Setup & Troubleshooting\n" +
"═══════════════════════════════════════════════════════════════\n" +
"\n" +
"QUICK SETUP  —  Claude Code (CLI)\n" +
"─────────────────────────────────\n" +
"1. Enable the MCP server with the toggle above and click Apply.\n" +
"2. Click \"Copy CLI Command\" and run it in your terminal:\n" +
"\n" +
"   claude mcp add --transport http secretsifter-desktop \\\n" +
"     http://localhost:<PORT>/mcp \\\n" +
"     --header \"Authorization: Bearer <your-token>\"\n" +
"\n" +
"3. Restart Claude Code (exit and reopen, or start a new session).\n" +
"\n" +
"4. Verify the connection:\n" +
"   claude mcp list\n" +
"   → secretsifter-desktop: ✓ Connected\n" +
"\n" +
"QUICK SETUP  —  Claude Desktop\n" +
"───────────────────────────────\n" +
"1. Click \"Copy JSON\" to copy the mcpServers block.\n" +
"2. Paste into:\n" +
"   Windows: %APPDATA%\\Claude\\claude_desktop_config.json\n" +
"3. Restart Claude Desktop.\n" +
"\n" +
"NOTE: If you also use the Burp extension, it registers as\n" +
"  \"secretsifter\" — both can coexist in the same config file.\n" +
"\n" +
"REGISTRATION COMMANDS\n" +
"──────────────────────\n" +
"Add:\n" +
"  claude mcp add --transport http secretsifter-desktop \\\n" +
"    http://localhost:<PORT>/mcp \\\n" +
"    --header \"Authorization: Bearer <your-token>\"\n" +
"\n" +
"Remove:\n" +
"  claude mcp remove secretsifter-desktop\n" +
"\n" +
"List all:\n" +
"  claude mcp list\n" +
"\n" +
"WINDOWS  —  PowerShell\n" +
"───────────────────────\n" +
"  claude mcp add --transport http secretsifter-desktop `\n" +
"    http://localhost:<PORT>/mcp `\n" +
"    --header \"Authorization: Bearer <your-token>\"\n" +
"\n" +
"TRIAGING  —  \"Failed to connect\"\n" +
"──────────────────────────────────\n" +
"□ Is the MCP server toggle enabled and Applied?\n" +
"□ Did you restart Claude after running 'claude mcp add'?\n" +
"□ Token mismatch? Remove and re-register:\n" +
"    claude mcp remove secretsifter-desktop\n" +
"    (click 'Copy CLI Command' and re-run)\n" +
"□ Port conflict? Check if another process is listening:\n" +
"    netstat -ano | findstr <PORT>\n" +
"□ Test the server manually with curl:\n" +
"\n" +
"  curl -s -X POST http://localhost:<PORT>/mcp \\\n" +
"    -H \"Content-Type: application/json\" \\\n" +
"    -H \"Authorization: Bearer <your-token>\" \\\n" +
"    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\n" +
"          \"params\":{\"protocolVersion\":\"2025-06-18\",\n" +
"          \"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}'\n" +
"\n" +
"  Expected: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{...}}\n" +
"  If 401: wrong token — regenerate and re-register.\n" +
"  If refused: server not running — check the toggle.\n" +
"\n" +
"REST API  (Python / curl automation)\n" +
"──────────────────────────────────────\n" +
"  POST   /api/scan          Start a scan\n" +
"  GET    /api/scan/status   Poll scan progress\n" +
"  DELETE /api/scan          Cancel scan\n" +
"  GET    /api/findings      Get all findings\n" +
"  DELETE /api/findings      Clear all findings\n" +
"  PATCH  /api/findings/{n}  Update finding severity\n" +
"  DELETE /api/findings/{n}  Delete one finding\n" +
"  POST   /api/report        Export CSV/JSON/HTML report\n" +
"  GET    /api/settings      Read settings\n" +
"  PATCH  /api/settings      Update settings\n" +
"  GET    /api/targets       Per-target scan outcomes\n" +
"  GET    /api/rules         Get custom rules\n" +
"  PUT    /api/rules         Replace custom rules\n" +
"  POST   /api/rules         Add one custom rule\n" +
"  GET    /api/logs          Read log buffer\n" +
"  DELETE /api/logs          Clear log buffer\n" +
"\n" +
"TOKEN LIFECYCLE\n" +
"────────────────\n" +
"• The token persists across app restarts (stored in Java Preferences).\n" +
"• Re-register Claude only when you click 'Regenerate Token'.\n" +
"• Server binds to localhost only — not reachable from the network.\n";
    }

    /** Search bar with highlight cycling (Enter = next, Shift+Enter = previous). */
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
        Highlighter.HighlightPainter curPainter =
                new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 140, 0));

        List<Integer> matches = new ArrayList<>();
        int[] cur = {0};

        Runnable repaint = () -> {
            highlighter.removeAllHighlights();
            int len = field.getText().trim().length();
            if (len == 0 || matches.isEmpty()) return;
            for (int i = 0; i < matches.size(); i++) {
                int pos = matches.get(i);
                try { highlighter.addHighlight(pos, pos + len, i == cur[0] ? curPainter : allPainter); }
                catch (BadLocationException ignored) {}
            }
        };

        Runnable scrollTo = () -> {
            if (matches.isEmpty()) return;
            int pos = matches.get(cur[0]);
            int len = field.getText().trim().length();
            area.setCaretPosition(pos + len);
            area.moveCaretPosition(pos);
            result.setText("\u2713 " + (cur[0] + 1) + " / " + matches.size());
            result.setForeground(new Color(0, 130, 0));
        };

        Runnable doSearch = () -> {
            String query = field.getText().trim();
            matches.clear();
            cur[0] = 0;
            highlighter.removeAllHighlights();
            if (query.isEmpty()) { result.setText(" "); result.setForeground(Color.GRAY); area.select(0, 0); return; }
            String content = area.getText().toLowerCase();
            String q = query.toLowerCase();
            int idx = 0;
            while ((idx = content.indexOf(q, idx)) >= 0) { matches.add(idx); idx += q.length(); }
            if (matches.isEmpty()) { result.setText("\u2717 Not found"); result.setForeground(new Color(180, 0, 0)); area.select(0, 0); }
            else { repaint.run(); scrollTo.run(); }
        };

        field.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { doSearch.run(); }
            public void removeUpdate(DocumentEvent e)  { doSearch.run(); }
            public void changedUpdate(DocumentEvent e) { doSearch.run(); }
        });

        field.addKeyListener(new KeyAdapter() {
            @Override public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() != KeyEvent.VK_ENTER || matches.isEmpty()) return;
                cur[0] = e.isShiftDown()
                        ? (cur[0] - 1 + matches.size()) % matches.size()
                        : (cur[0] + 1) % matches.size();
                repaint.run();
                scrollTo.run();
            }
        });
        return bar;
    }

    // =========================================================================
    // Auto-save wiring
    // =========================================================================

    private void wireAutoSave() {
        enabledBox.addActionListener(e -> settings.setEnabled(enabledBox.isSelected()));

        tierCombo.addActionListener(e -> {
            Object sel = tierCombo.getSelectedItem();
            if (sel != null) try { settings.setTier(ScanSettings.ScanTier.valueOf((String) sel)); } catch (Exception ignored) {}
        });

        entropySpinner.addChangeListener(e ->
                settings.setEntropyThreshold(((Number) entropySpinner.getValue()).doubleValue()));

        piiBox.addActionListener(e -> settings.setPiiEnabled(piiBox.isSelected()));
        scanRequestsBox.addActionListener(e -> settings.setScanRequestsEnabled(scanRequestsBox.isSelected()));
        liveValidateBox.addActionListener(e -> settings.setLiveValidationEnabled(liveValidateBox.isSelected()));

        urlTimeoutCombo.addActionListener(e -> {
            int idx = urlTimeoutCombo.getSelectedIndex();
            if (idx >= 0 && idx < URL_TIMEOUT_SECONDS.length)
                settings.setUrlTimeoutSeconds(URL_TIMEOUT_SECONDS[idx]);
        });

        pwEnabledBox.addActionListener(e -> settings.setPlaywrightEnabled(pwEnabledBox.isSelected()));
        maxPagesSpinner.addChangeListener(e ->
                settings.setPlaywrightMaxPages(((Number) maxPagesSpinner.getValue()).intValue()));
        browserPathField.getDocument().addDocumentListener(newDocListener(
                () -> settings.setBrowserPath(browserPathField.getText().trim())));

        customRulesEnabledBox.addActionListener(e ->
                settings.setCustomRulesEnabled(customRulesEnabledBox.isSelected()));
        customRulesOnlyBox.addActionListener(e ->
                settings.setCustomRulesOnly(customRulesOnlyBox.isSelected()));

        customRulesArea.getDocument().addDocumentListener(newDocListener(() -> {
            List<String> rules = new ArrayList<>();
            for (String line : customRulesArea.getText().split("\n")) {
                String t = line.trim();
                if (!t.isEmpty() && !t.startsWith("#")) rules.add(t);
            }
            settings.setCustomRules(rules);
        }));

        cdnArea.getDocument().addDocumentListener(newDocListener(() -> {
            List<String> cdn = new ArrayList<>();
            for (String line : cdnArea.getText().split("\n")) { String t = line.trim(); if (!t.isEmpty()) cdn.add(t); }
            settings.setCdnBlocklist(cdn);
        }));

        keyBlocklistArea.getDocument().addDocumentListener(newDocListener(() -> {
            List<String> list = new ArrayList<>();
            for (String line : keyBlocklistArea.getText().split("\n")) { String t = line.trim(); if (!t.isEmpty()) list.add(t); }
            settings.setKeyBlocklist(list);
        }));

        keyAllowlistArea.getDocument().addDocumentListener(newDocListener(() -> {
            List<String> list = new ArrayList<>();
            for (String line : keyAllowlistArea.getText().split("\n")) { String t = line.trim(); if (!t.isEmpty()) list.add(t); }
            settings.setKeyAllowlist(list);
        }));

        // Update config area when port spinner changes
        mcpPortSpinner.addChangeListener(e -> {
            if (mcpConfigArea != null) mcpConfigArea.setText(buildMcpConfigJson());
        });
    }

    private static DocumentListener newDocListener(Runnable action) {
        return new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { action.run(); }
            @Override public void removeUpdate(DocumentEvent e)  { action.run(); }
            @Override public void changedUpdate(DocumentEvent e) { action.run(); }
        };
    }
}
