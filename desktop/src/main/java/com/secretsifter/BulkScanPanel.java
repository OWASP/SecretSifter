package com.secretsifter;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bulk Scan tab — paste or import a list of URLs, fetches and scans each one,
 * extracts inline scripts + script-src files + webpack chunk references, and
 * presents findings in a live results table.
 *
 * Standalone version: Montoya API, ScopeMonitor, and Burp site-map integration
 * removed. HTTP fetching is handled by {@link HttpFetcher}.
 */
public class BulkScanPanel {

    // ── Columns ───────────────────────────────────────────────────────────────
    private static final String[] COLS = {
        "Issue ID", "Severity", "Confidence", "Validation", "Rule ID", "Key", "Value", "URL", "Target", "Line", "Context", ""
    };
    // Issue ID: permanent per secret (SS-102426-7K4M2Q), the same in every scan; see core.IssueRegistry.
    private static final int COL_SEV    = 1;
    private static final int COL_CONF   = 2;
    private static final int COL_VALID  = 3;
    private static final int COL_VAL    = 6;
    private static final int COL_URL    = 7;
    private static final int COL_TARGET = 8;
    private static final int COL_DEL    = 11;

    // ── Column visibility ─────────────────────────────────────────────────────
    // Indices 1-10 are toggleable; 0 (#) and 11 (delete) are always visible.
    private static final int[] TOGGLEABLE_COLS = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    /** TableColumn objects removed from the view, keyed by original model index. */
    private final Map<Integer, javax.swing.table.TableColumn> hiddenColumns = new LinkedHashMap<>();
    /** Snapshot of all TableColumn objects in original order, populated after table init. */
    private javax.swing.table.TableColumn[] allColumns;

    // ── State ─────────────────────────────────────────────────────────────────
    private final SecretScanner  scanner;
    private final ScanSettings   settings;
    private final HttpFetcher    fetcher;
    private final AppLogger      logger;
    private final CaptureStore   captureStore = new CaptureStore();

    private final DefaultTableModel              tableModel;
    private TableRowSorter<DefaultTableModel>    rowSorter;
    private final List<SecretFinding> tableFindings = Collections.synchronizedList(new ArrayList<>());
    private final AtomicBoolean       running       = new AtomicBoolean(false);
    private final AtomicInteger       urlsDone      = new AtomicInteger(0);
    private final AtomicInteger       jsDiscovered  = new AtomicInteger(0);
    private final AtomicInteger       jsFetched     = new AtomicInteger(0);
    private volatile ExecutorService  executor;
    private volatile boolean          wasBrowserMode = false;
    private final AtomicBoolean       paused         = new AtomicBoolean(false);
    /** Guards against onScanComplete being called twice (stop + consumer finally). */
    private final AtomicBoolean       scanCompleting = new AtomicBoolean(false);
    private final Set<String>         seenUrls      = ConcurrentHashMap.newKeySet();
    /** Persistent dedup: same ruleId+value+sourceUrl is never shown twice, even across rescans.
     *  Only cleared when the user explicitly clears all findings. */
    private final Set<String>         seenValueLines = ConcurrentHashMap.newKeySet();

    // ── Status counters ───────────────────────────────────────────────────────
    private final AtomicInteger statusScanned = new AtomicInteger(0);
    private final AtomicInteger statusFailed  = new AtomicInteger(0);
    private final AtomicInteger statusAuth    = new AtomicInteger(0);

    // ── Masking flags ─────────────────────────────────────────────────────────
    private boolean maskValues = false;
    private boolean maskUrls   = false;

    // ── Swing controls ────────────────────────────────────────────────────────
    private JPanel    rootPanel;
    private JTextArea urlArea;
    private JSpinner  concurrencySpinner;
    private ToggleSwitch followScriptSrcBox;
    private ToggleSwitch followChunksBox;
    private ToggleSwitch browserModeBox;
    private ToggleSwitch crossOriginApisBox;
    private ToggleSwitch strictScopeBox;
    private ToggleSwitch validateBox;
    private JButton   startBtn;
    private JButton   stopBtn;
    private JButton   pauseBtn;
    private JProgressBar progressBar;
    private JLabel    statusLabel;
    private JLabel    timerLabel;
    private JLabel    currentFileLabel;
    private javax.swing.Timer scanTimer;
    private long      scanStartMs;
    private JTable    resultsTable;

    // ── Details side panel ────────────────────────────────────────────────────
    private JLabel    detailsTitle;
    private JTextArea requestPane;
    private JTextArea responsePane;
    private JTextField requestSearch;
    private JTextField responseSearch;
    private JComboBox<String> detailsSevCombo;
    private JComboBox<String> detailsConfCombo;
    // Inline form fields rendered inside the Details tab (replacing the old
    // JEditorPane HTML view so the matched value can wrap and so copy buttons sit
    // next to their URLs / value).
    private JTextField detailsRuleIdField;
    private JTextField detailsRuleNameField;
    private JTextField detailsKeyField;
    private JTextField detailsLineField;
    private JTextField detailsSourceUrlField;
    private JTextField detailsTargetUrlField;
    private JTextArea  detailsValueArea;
    private JTextArea  detailsContextArea;
    private int currentDetailsModelRow = -1;
    /** Guards against feedback loops between table edits and details-panel combo edits. */
    private boolean detailsSyncing = false;

    // ── Target Status table ───────────────────────────────────────────────────
    private DefaultTableModel targetStatusModel;

    // ── Summary bar labels ────────────────────────────────────────────────────
    private JLabel sumScannedLbl;
    private JLabel sumFailedLbl;
    private JLabel sumAuthLbl;

    // ── Severity count badge labels ───────────────────────────────────────────
    private JLabel highCountLbl;
    private JLabel critCountLbl;
    private JLabel medCountLbl;
    private JLabel lowCountLbl;
    private JLabel infoCountLbl;

    // ── Severity colours ──────────────────────────────────────────────────────
    private static final Map<String, Color> SEV_BG = Map.ofEntries(
            Map.entry("CRITICAL",    new Color(255, 195, 215)),
            Map.entry("HIGH",        new Color(255, 215, 215)),
            Map.entry("MEDIUM",      new Color(255, 235, 200)),
            Map.entry("LOW",         new Color(255, 252, 200)),
            Map.entry("INFORMATION", new Color(220, 235, 255)),
            Map.entry("INFO",        new Color(220, 235, 255)),
            Map.entry("NOISE",       new Color(225, 225, 225))   // grey out marker
    );

    /** Saturated badge fill colours (white text on top). */
    private static final Map<String, Color> SEV_BADGE = Map.ofEntries(
            Map.entry("CRITICAL",    new Color(150,   0,  80)),
            Map.entry("HIGH",        new Color(210,  45,  45)),
            Map.entry("MEDIUM",      new Color(210, 115,   0)),
            Map.entry("LOW",         new Color(130, 115,   0)),
            Map.entry("INFORMATION", new Color( 40, 105, 195)),
            Map.entry("INFO",        new Color( 40, 105, 195)),
            Map.entry("NOISE",       new Color(110, 110, 110))   // dim grey badge
    );

    // =========================================================================

    public BulkScanPanel(SecretScanner scanner, ScanSettings settings,
                          HttpFetcher fetcher, AppLogger logger) {
        this.scanner  = scanner;
        this.settings = settings;
        this.fetcher  = fetcher;
        this.logger   = logger;

        tableModel = new DefaultTableModel(COLS, 0) {
            @Override public boolean isCellEditable(int r, int c) {
                return c == COL_SEV || c == COL_CONF;
            }
        };

        if (SwingUtilities.isEventDispatchThread()) buildUi();
        else try { SwingUtilities.invokeAndWait(this::buildUi); }
             catch (Exception e) { SwingUtilities.invokeLater(this::buildUi); }
    }

    public JPanel getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    public List<SecretFinding> getFindings() {
        synchronized (tableFindings) {
            return new ArrayList<>(tableFindings);
        }
    }

    /**
     * Returns a snapshot of the Target Status table as a list of JSON objects,
     * each with "icon", "host", and "detail" fields.
     * Safe to call from any thread.
     */
    public List<org.json.JSONObject> getTargetStatuses() {
        List<org.json.JSONObject> result = new ArrayList<>();
        if (targetStatusModel == null) return result;
        int rows = targetStatusModel.getRowCount();
        for (int i = 0; i < rows; i++) {
            Object icon   = targetStatusModel.getValueAt(i, 0);
            Object host   = targetStatusModel.getValueAt(i, 1);
            Object detail = targetStatusModel.getValueAt(i, 2);
            result.add(new org.json.JSONObject()
                    .put("icon",   icon   != null ? icon.toString()   : "")
                    .put("host",   host   != null ? host.toString()   : "")
                    .put("detail", detail != null ? detail.toString() : ""));
        }
        return result;
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(8, 8));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ── Left: URL input (top) + Target Status (bottom) in a split ────────
        JPanel inputPanel = new JPanel(new BorderLayout(4, 4));
        TitledBorder targetUrlsBorder = new TitledBorder("Target URLs  (one per line, 30 max)");
        targetUrlsBorder.setTitleFont(SecretSifterApp.UI_BOLD_11);
        inputPanel.setBorder(targetUrlsBorder);

        urlArea = new JTextArea();
        urlArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        urlArea.setLineWrap(false);
        urlArea.setToolTipText("Paste URLs or hostnames, one per line");
        inputPanel.add(new JScrollPane(urlArea), BorderLayout.CENTER);

        JPanel urlBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton importBtn   = new JButton("Import File…");
        JButton scanHarBtn  = new JButton("Scan HAR…");
        JButton clearUrlBtn = new JButton("Clear");
        importBtn.addActionListener(e -> importUrlFile());
        scanHarBtn.addActionListener(e -> importAndScanHar());
        clearUrlBtn.addActionListener(e -> urlArea.setText(""));
        urlBtns.add(importBtn);
        urlBtns.add(scanHarBtn);
        urlBtns.add(clearUrlBtn);
        inputPanel.add(urlBtns, BorderLayout.SOUTH);

        // ── Target Status table ───────────────────────────────────────────────
        targetStatusModel = new DefaultTableModel(new String[]{"", "URL", "Detail"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable statusTable = new JTable(targetStatusModel);
        statusTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        statusTable.setRowHeight(20);
        statusTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        statusTable.getTableHeader().setReorderingAllowed(false);
        statusTable.getColumnModel().getColumn(0).setPreferredWidth(26);
        statusTable.getColumnModel().getColumn(0).setMaxWidth(26);
        statusTable.getColumnModel().getColumn(1).setPreferredWidth(192);
        statusTable.getColumnModel().getColumn(2).setPreferredWidth(70);

        // Render status icons as colored symbols — monospaced font can't display emoji
        statusTable.getColumnModel().getColumn(0).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                String val = v == null ? "" : v.toString();
                String sym; Color fg;
                if      (val.contains("✅")) { sym = "✔"; fg = new Color(0, 180, 80);   }
                else if (val.contains("❌")) { sym = "✖"; fg = new Color(210, 50, 50);  }
                else if (val.contains("🔒")) { sym = "●"; fg = new Color(255, 180, 0);  }
                else                         { sym = val; fg = Color.LIGHT_GRAY;         }
                super.getTableCellRendererComponent(t, sym, sel, foc, r, c);
                setHorizontalAlignment(CENTER);
                setFont(new Font("Segoe UI Symbol", Font.BOLD, 13));
                if (!sel) setForeground(fg);
                return this;
            }
        });

        JPanel statusTablePanel = new JPanel(new BorderLayout());
        statusTablePanel.setBorder(new TitledBorder("Target Status"));
        statusTablePanel.add(new JScrollPane(statusTable,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED), BorderLayout.CENTER);

        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, inputPanel, statusTablePanel);
        leftSplit.setDividerLocation(260);
        leftSplit.setResizeWeight(0.6);
        leftSplit.setPreferredSize(new Dimension(310, 0));

        // ── Top: options bar ───────────────────────────────────────────────
        JPanel optPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        optPanel.setBorder(new TitledBorder("Scan Options"));

        JLabel threadsLbl = new JLabel("Threads:");
        threadsLbl.setForeground(new Color(210, 210, 210));
        optPanel.add(threadsLbl);
        concurrencySpinner = new JSpinner(new SpinnerNumberModel(25, 1, 50, 1));
        concurrencySpinner.setPreferredSize(new Dimension(55, 24));
        optPanel.add(concurrencySpinner);

        followScriptSrcBox = new ToggleSwitch("Follow script-src", true);
        followScriptSrcBox.setForeground(new Color(210, 210, 210));
        followScriptSrcBox.setToolTipText("Fetch and scan all external JS files referenced in HTML <script src>");
        optPanel.add(followScriptSrcBox);

        followChunksBox = new ToggleSwitch("Follow chunks", true);
        followChunksBox.setForeground(new Color(210, 210, 210));
        followChunksBox.setToolTipText("Follow webpack/Next.js chunk references inside JS bundles (depth 1)");
        optPanel.add(followChunksBox);

        // Browser Mode defaults ON
        browserModeBox = new ToggleSwitch("Browser Mode", true);
        browserModeBox.setForeground(new Color(210, 210, 210));
        browserModeBox.setToolTipText(
                "Use a headless browser (Playwright) to discover ALL JS — dynamic chunks,\n" +
                "SPA routes, lazy-loaded scripts.\n" +
                "Uses Microsoft Edge automatically on Windows 10/11 — no setup required.");
        browserModeBox.addActionListener(e -> onBrowserModeToggled());
        optPanel.add(browserModeBox);
        SwingUtilities.invokeLater(this::onBrowserModeToggled);

        crossOriginApisBox = new ToggleSwitch("Cross-origin APIs", settings.isFollowCrossOriginApis());
        crossOriginApisBox.setForeground(new Color(210, 210, 210));
        crossOriginApisBox.setToolTipText(
                "Scan API responses from cross-origin domains called by the target page\n" +
                "(e.g. app.example.com calling api.other-service.com).\n" +
                "Equivalent to Burp's 'Process cross-origin API requests' option.\n" +
                "May increase false positives from third-party services.");
        crossOriginApisBox.addActionListener(e -> settings.setFollowCrossOriginApis(crossOriginApisBox.isSelected()));
        optPanel.add(crossOriginApisBox);

        strictScopeBox = new ToggleSwitch("Strict Scope", settings.isStrictScope());
        strictScopeBox.setForeground(new Color(210, 210, 210));
        strictScopeBox.setToolTipText(
                "Restrict JS capture to the exact host being scanned (browser mode).\n" +
                "OFF: allows JS from subdomains sharing the same registrable domain\n" +
                "     (e.g. static.example.com when scanning app.example.com).\n" +
                "ON:  only captures JS from the exact seed host — equivalent to Burp's\n" +
                "     strict target scope. Reduces noise but may miss CDN-hosted app JS.");
        strictScopeBox.addActionListener(e -> settings.setStrictScope(strictScopeBox.isSelected()));
        optPanel.add(strictScopeBox);

        validateBox = new ToggleSwitch("Validate", settings.isValidationEnabled());
        validateBox.setForeground(new Color(210, 210, 210));
        validateBox.setToolTipText(
                "Check detected secrets to see whether they are still active.\n" +
                "Offline checks (JWT expiry, Luhn) run with no network calls.\n" +
                "Live provider checks (AWS, Stripe, GitHub, ...) run only when\n" +
                "'Allow live (network) validation' is also enabled in Settings.\n" +
                "Results appear in the Validation column: active / dead / restricted / unknown.");
        validateBox.addActionListener(e -> onValidateToggled());
        optPanel.add(validateBox);

        optPanel.add(Box.createHorizontalStrut(10));

        startBtn = new JButton("Start Scan");
        stopBtn  = new JButton("Stop");
        pauseBtn = new JButton("Pause");
        stopBtn.setEnabled(false);
        pauseBtn.setEnabled(false);
        startBtn.addActionListener(e -> startScan());
        stopBtn.addActionListener(e  -> stopScan());
        pauseBtn.addActionListener(e -> togglePause());
        optPanel.add(startBtn);
        optPanel.add(stopBtn);
        optPanel.add(pauseBtn);

        // ── Summary bar ────────────────────────────────────────────────────
        JPanel summaryBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 3));
        sumScannedLbl = new JLabel("Scanned: 0");
        sumFailedLbl  = new JLabel("Failed: 0");
        sumAuthLbl    = new JLabel("Auth: 0");
        sumScannedLbl.setForeground(new Color(80, 200, 120));
        sumFailedLbl .setForeground(new Color(220, 80,  80));
        sumAuthLbl   .setForeground(new Color(255, 200, 80));
        for (JLabel l : new JLabel[]{sumScannedLbl, sumFailedLbl, sumAuthLbl}) {
            l.setFont(SecretSifterApp.UI_BOLD_12);
            summaryBar.add(l);
        }

        // ── Centre: results table ──────────────────────────────────────────
        resultsTable = new JTable(tableModel) {
            @Override public boolean getScrollableTracksViewportWidth() {
                return getPreferredSize().width < getParent().getWidth();
            }
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                if (tableModel.getRowCount() == 0) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                            RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                    g2.setColor(new Color(130, 130, 130));
                    g2.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
                    String msg = "No findings yet  ·  Paste URLs on the left and click  Start Scan";
                    FontMetrics fm = g2.getFontMetrics();
                    g2.drawString(msg,
                            (getWidth()  - fm.stringWidth(msg)) / 2,
                            Math.max(60, getHeight() / 3));
                    g2.dispose();
                }
            }
        };
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        resultsTable.setRowHeight(24);
        resultsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setDefaultRenderer(Object.class, new SeverityCellRenderer());
        resultsTable.getColumnModel().getColumn(COL_SEV).setCellRenderer(new SeverityBadgeRenderer());
        resultsTable.getColumnModel().getColumn(COL_DEL).setCellRenderer(new DeleteButtonRenderer());
        resultsTable.getTableHeader().setReorderingAllowed(false);

        // ── Row sorter: enables clickable-header sorting ───────────────────────
        rowSorter = new TableRowSorter<>(tableModel);
        // Custom severity order: CRITICAL > HIGH > MEDIUM > LOW > INFORMATION
        Comparator<Object> sevOrder = (a, b) -> sevRank(String.valueOf(b)) - sevRank(String.valueOf(a));
        rowSorter.setComparator(COL_SEV, sevOrder);
        // Issue ID column sorts by issue date+serial (SS-MMDDYY-XXXXXX)
        rowSorter.setComparator(0, Comparator.comparing(o -> issueIdSortKey(String.valueOf(o))));
        resultsTable.setRowSorter(rowSorter);

        int[] widths = { 140, 65, 75, 90, 130, 130, 220, 220, 180, 45, 200, 28 };
        for (int i = 0; i < widths.length && i < resultsTable.getColumnCount(); i++) {
            resultsTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        // Fix delete column width
        resultsTable.getColumnModel().getColumn(COL_DEL).setMaxWidth(28);
        resultsTable.getColumnModel().getColumn(COL_DEL).setMinWidth(28);

        // Snapshot all columns in original order for show/hide toggles
        allColumns = new javax.swing.table.TableColumn[COLS.length];
        for (int i = 0; i < COLS.length; i++) {
            allColumns[i] = resultsTable.getColumnModel().getColumn(i);
        }

        // ── Dropdown editors for Severity and Confidence ───────────────────────
        // NOISE in either column marks the row as a false-positive: it is greyed out
        // in the table, ranked below INFORMATION in the severity filter, and excluded
        // from HTML / CSV / JSON exports.
        JComboBox<String> sevCombo = new JComboBox<>(
                new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION", "NOISE"});
        sevCombo.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        resultsTable.getColumnModel().getColumn(COL_SEV)
                .setCellEditor(new DefaultCellEditor(sevCombo));

        JComboBox<String> confCombo = new JComboBox<>(
                new String[]{"CERTAIN", "FIRM", "TENTATIVE", "NOISE"});
        confCombo.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        resultsTable.getColumnModel().getColumn(COL_CONF)
                .setCellEditor(new DefaultCellEditor(confCombo));

        // Keep tableFindings, the details side-panel, and badge counts in sync whenever
        // the user edits Severity / Confidence in the table cell editor.  Without this,
        // the underlying SecretFinding records and the right-hand details combos would
        // drift out of step with what's shown in the row.
        tableModel.addTableModelListener(e -> {
            int col = e.getColumn();
            if (col != COL_SEV && col != COL_CONF) return;
            int row = e.getFirstRow();
            if (row < 0) return;
            SwingUtilities.invokeLater(() -> {
                synchronized (tableFindings) {
                    if (row < tableFindings.size()) {
                        SecretFinding old = tableFindings.get(row);
                        String sev  = String.valueOf(tableModel.getValueAt(row, COL_SEV));
                        String conf = String.valueOf(tableModel.getValueAt(row, COL_CONF));
                        tableFindings.set(row, old.withSeverity(sev).withConfidence(conf));
                        // If the edited row is the one currently rendered in the details
                        // side-panel, push the new severity/confidence into the combos so
                        // both views stay aligned.
                        if (row == currentDetailsModelRow && detailsSevCombo != null) {
                            detailsSyncing = true;
                            detailsSevCombo.setSelectedItem(sev);
                            detailsConfCombo.setSelectedItem(conf);
                            detailsSyncing = false;
                        }
                    }
                }
                updateCountBadges();
                resultsTable.repaint();   // redraw NOISE rows in grey
            });
        });

        // Right-click context menu
        JPopupMenu tableMenu = new JPopupMenu();
        JMenuItem copyValItem = new JMenuItem("Copy Value");
        JMenuItem copyRowItem = new JMenuItem("Copy Row");
        JMenuItem openUrlItem = new JMenuItem("Open URL in Browser");
        copyValItem.addActionListener(e -> copyTableCell(COL_VAL));
        copyRowItem.addActionListener(e -> copyTableRow());
        openUrlItem.addActionListener(e -> openUrlInBrowser());
        tableMenu.add(copyValItem);
        tableMenu.add(copyRowItem);
        tableMenu.addSeparator();
        tableMenu.add(openUrlItem);

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseReleased(MouseEvent e) {
                int row = resultsTable.rowAtPoint(e.getPoint());
                int col = resultsTable.columnAtPoint(e.getPoint());
                if (e.isPopupTrigger()) {
                    if (row >= 0) resultsTable.setRowSelectionInterval(row, row);
                    tableMenu.show(e.getComponent(), e.getX(), e.getY());
                } else if (!e.isPopupTrigger() && row >= 0 && col == COL_DEL) {
                    // Delete this finding row — convert view index → model index (sorter may reorder)
                    int modelRow = resultsTable.convertRowIndexToModel(row);
                    if (modelRow < tableModel.getRowCount()) {
                        tableModel.removeRow(modelRow);
                        synchronized (tableFindings) {
                            if (modelRow < tableFindings.size()) tableFindings.remove(modelRow);
                        }
                        updateCountBadges();
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(resultsTable,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // ── Findings header with badges and eye-toggle ─────────────────────
        critCountLbl = makeSevBadge("CRITICAL",    0);
        highCountLbl = makeSevBadge("HIGH",        0);
        medCountLbl  = makeSevBadge("MEDIUM",      0);
        lowCountLbl  = makeSevBadge("LOW",         0);
        infoCountLbl = makeSevBadge("INFORMATION", 0);

        // Severity filter combo
        JComboBox<String> sevFilterCombo = new JComboBox<>(new String[]{
                "All Severities", "Critical+", "High+", "Medium+", "Low+"
        });
        sevFilterCombo.setFont(SecretSifterApp.UI_BOLD_11);
        sevFilterCombo.setToolTipText("Filter findings by minimum severity");
        sevFilterCombo.addActionListener(e -> {
            int minRank = switch ((String) sevFilterCombo.getSelectedItem()) {
                case "Critical+" -> 5;
                case "High+"     -> 4;
                case "Medium+"   -> 3;
                case "Low+"      -> 2;
                default          -> 0;
            };
            if (minRank == 0) {
                rowSorter.setRowFilter(null);
            } else {
                rowSorter.setRowFilter(RowFilter.regexFilter(".*")); // reset first
                final int mr = minRank;
                rowSorter.setRowFilter(new RowFilter<DefaultTableModel, Integer>() {
                    @Override public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                        return sevRank(String.valueOf(entry.getValue(COL_SEV))) >= mr;
                    }
                });
            }
        });

        // Mask toggles + Columns menu — placed inline with the badges & severity filter
        // so the entire findings toolbar stays on a single left-aligned row.
        JToggleButton maskValBtn = new JToggleButton("Mask Value");
        maskValBtn.setToolTipText("Toggle masking of secret values");
        maskValBtn.setFont(SecretSifterApp.UI_BOLD_11);
        maskValBtn.setForeground(Color.WHITE);
        maskValBtn.addActionListener(e -> {
            maskValues = maskValBtn.isSelected();
            resultsTable.repaint();
        });

        JToggleButton maskUrlBtn = new JToggleButton("Mask URL");
        maskUrlBtn.setToolTipText("Toggle masking of URLs");
        maskUrlBtn.setFont(SecretSifterApp.UI_BOLD_11);
        maskUrlBtn.setForeground(Color.WHITE);
        maskUrlBtn.addActionListener(e -> {
            maskUrls = maskUrlBtn.isSelected();
            resultsTable.repaint();
        });

        JButton columnsHdrBtn = new JButton("Columns ▾");
        columnsHdrBtn.setFont(SecretSifterApp.UI_BOLD_11);
        columnsHdrBtn.setToolTipText("Show or hide columns");
        JPopupMenu columnsHdrMenu = new JPopupMenu();
        for (int idx : TOGGLEABLE_COLS) {
            JCheckBoxMenuItem item = new JCheckBoxMenuItem(COLS[idx], true);
            final int colIdx = idx;
            item.addActionListener(e -> toggleColumn(colIdx, item.isSelected()));
            columnsHdrMenu.add(item);
        }
        columnsHdrBtn.addActionListener(e ->
                columnsHdrMenu.show(columnsHdrBtn, 0, columnsHdrBtn.getHeight()));

        // Single-row toolbar:  Findings [badges] | Show: [combo] [Columns ▾] [Mask Value] [Mask URL]
        JPanel badgesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        badgesPanel.add(new JLabel("Findings"));
        badgesPanel.add(critCountLbl);
        badgesPanel.add(highCountLbl);
        badgesPanel.add(medCountLbl);
        badgesPanel.add(lowCountLbl);
        badgesPanel.add(infoCountLbl);
        badgesPanel.add(Box.createHorizontalStrut(8));
        badgesPanel.add(new JLabel("Show:"));
        badgesPanel.add(sevFilterCombo);
        badgesPanel.add(Box.createHorizontalStrut(4));
        badgesPanel.add(columnsHdrBtn);
        badgesPanel.add(maskValBtn);
        badgesPanel.add(maskUrlBtn);

        JPanel findingsHeader = new JPanel(new BorderLayout());
        findingsHeader.add(badgesPanel, BorderLayout.WEST);

        // ── Details side panel (Details / Request / Response tabs) ────────────
        JPanel detailsSide = buildDetailsPanel();
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow < 0) { currentDetailsModelRow = -1; updateDetailsPanel(null); return; }
            try {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < tableFindings.size()) {
                    currentDetailsModelRow = modelRow;
                    updateDetailsPanel(tableFindings.get(modelRow));
                }
            } catch (Exception ignored) {}
        });

        JSplitPane centreSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, detailsSide);
        centreSplit.setResizeWeight(0.60);
        centreSplit.setDividerLocation(820);
        centreSplit.setContinuousLayout(true);
        centreSplit.setOneTouchExpandable(true);
        centreSplit.setDividerSize(10);
        // Hard floor on both sides so dragging the divider can never collapse either
        // pane completely — Details was previously getting hidden behind the right
        // edge when users dragged left to widen the table or open Request/Response.
        tableScroll.setMinimumSize(new Dimension(420, 200));
        detailsSide.setMinimumSize(new Dimension(380, 200));

        JPanel centrePanel = new JPanel(new BorderLayout(4, 4));
        centrePanel.setBorder(BorderFactory.createTitledBorder(""));
        centrePanel.add(findingsHeader, BorderLayout.NORTH);
        centrePanel.add(centreSplit,    BorderLayout.CENTER);

        // ── Bottom: progress + export ──────────────────────────────────────
        JPanel bottomPanel = new JPanel(new BorderLayout(6, 4));

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("");
        progressBar.setPreferredSize(new Dimension(0, 18));
        progressBar.setUI(new javax.swing.plaf.basic.BasicProgressBarUI() {
            @Override protected Color getSelectionBackground() { return Color.WHITE; }
            @Override protected Color getSelectionForeground() { return Color.WHITE; }
        });
        progressBar.setForeground(new Color(220, 110, 10));

        timerLabel = new JLabel("");
        timerLabel.setForeground(Color.WHITE);
        timerLabel.setFont(SecretSifterApp.UI_BOLD_11);

        statusLabel = new JLabel("Ready.");
        statusLabel.setForeground(new Color(180, 180, 180));
        statusLabel.setFont(SecretSifterApp.UI_BOLD_11);

        currentFileLabel = new JLabel("");
        currentFileLabel.setForeground(new Color(80, 180, 255));
        currentFileLabel.setFont(SecretSifterApp.UI_BOLD_11);

        // Export dropdown button
        JButton exportHtmlDropBtn = new JButton("Export Reports  \u25BE");
        JPopupMenu exportMenu = new JPopupMenu();
        JMenuItem exportAllItem    = new JMenuItem("All-in-One Report (HTML + CSV + JSON ZIP)");
        JMenuItem exportDomainItem = new JMenuItem("Per-Domain Reports (HTMLs + CSV + JSON ZIP)");
        exportAllItem.addActionListener(e    -> exportHtml());
        exportDomainItem.addActionListener(e -> exportHtmlPerDomain());
        exportMenu.add(exportAllItem);
        exportMenu.add(exportDomainItem);
        exportHtmlDropBtn.addActionListener(e -> {
            exportMenu.show(exportHtmlDropBtn, 0, exportHtmlDropBtn.getHeight());
        });

        JButton exportDataDropBtn = new JButton("Export Data  \u25BE");
        JPopupMenu exportDataMenu = new JPopupMenu();
        JMenuItem exportCsvItem        = new JMenuItem("Export CSV");
        JMenuItem exportJsonItem       = new JMenuItem("Export JSON");
        JMenuItem exportSuppressedItem = new JMenuItem("Export Suppressed (NOISE) CSV");
        exportCsvItem.addActionListener(e        -> exportCsv());
        exportJsonItem.addActionListener(e       -> exportJson());
        exportSuppressedItem.addActionListener(e -> exportSuppressedCsv());
        exportDataMenu.add(exportCsvItem);
        exportDataMenu.add(exportJsonItem);
        exportDataMenu.addSeparator();
        exportDataMenu.add(exportSuppressedItem);
        exportDataDropBtn.addActionListener(e ->
                exportDataMenu.show(exportDataDropBtn, 0, exportDataDropBtn.getHeight()));

        // Columns ▾ button lives in the findings header (alongside Mask Value /
        // Mask URL); no duplicate copy in the bottom toolbar.

        JPanel exportBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton clearResultsBtn = new JButton("Clear Results");
        clearResultsBtn.addActionListener(e -> clearResults());
        exportBtns.add(clearResultsBtn);
        exportBtns.add(exportDataDropBtn);
        exportBtns.add(exportHtmlDropBtn);

        JPanel progressRow = new JPanel(new BorderLayout(6, 0));
        progressRow.add(progressBar, BorderLayout.CENTER);
        progressRow.add(timerLabel,  BorderLayout.EAST);

        JPanel infoRow = new JPanel(new BorderLayout(6, 0));
        infoRow.add(statusLabel,      BorderLayout.WEST);
        infoRow.add(currentFileLabel, BorderLayout.CENTER);

        JPanel statusPanel = new JPanel(new GridLayout(2, 1, 0, 2));
        statusPanel.add(progressRow);
        statusPanel.add(infoRow);

        bottomPanel.add(statusPanel, BorderLayout.CENTER);
        bottomPanel.add(exportBtns,  BorderLayout.EAST);

        // ── Assemble right area ────────────────────────────────────────────
        JPanel topArea = new JPanel(new BorderLayout(6, 6));
        topArea.add(optPanel,    BorderLayout.NORTH);

        // summaryBar sits between optPanel and centrePanel
        JPanel optAndSummary = new JPanel(new BorderLayout());
        optAndSummary.add(optPanel,    BorderLayout.NORTH);
        optAndSummary.add(summaryBar,  BorderLayout.SOUTH);

        JPanel rightArea = new JPanel(new BorderLayout(6, 6));
        rightArea.add(optAndSummary, BorderLayout.NORTH);
        rightArea.add(centrePanel,   BorderLayout.CENTER);
        rightArea.add(bottomPanel,   BorderLayout.SOUTH);

        // ── Main split: left (URL input + status) | right (everything else) ─
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplit, rightArea);
        split.setDividerLocation(310);
        split.setResizeWeight(0.0);

        rootPanel.add(split, BorderLayout.CENTER);
    }

    // =========================================================================
    // Scan orchestration
    // =========================================================================

    private void startScan() {
        List<String> urls = parseUrls();
        if (urls.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Please enter at least one URL to scan.",
                    "No URLs", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Auto-clear previous run's findings, dedup state, and capture store so a
        // fresh scan presents a clean dashboard.  Without this, re-running scan
        // appends to the existing rows and the persistent dedup ("seenValueLines")
        // silently suppresses identical findings from the new run, making the new
        // scan look like it found less than it actually did.
        if (!tableFindings.isEmpty() || tableModel.getRowCount() > 0) {
            clearResults();
        }

        running.set(true);
        paused.set(false);
        scanCompleting.set(false);
        urlsDone.set(0);
        jsDiscovered.set(0);
        jsFetched.set(0);
        statusScanned.set(0);
        statusFailed.set(0);
        statusAuth.set(0);
        seenUrls.clear();
        wasBrowserMode = browserModeBox.isSelected();
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        pauseBtn.setEnabled(wasBrowserMode);
        pauseBtn.setText("Pause");
        statusLabel.setForeground(new Color(80, 180, 255));

        // Reset target status table
        SwingUtilities.invokeLater(() -> {
            targetStatusModel.setRowCount(0);
            updateSummaryBar();
        });

        startScanTimer();

        if (wasBrowserMode) {
            startBrowserScan(urls);
        } else {
            progressBar.setIndeterminate(true);
            progressBar.setString("Scanning " + urls.size() + " URL(s)…");
            statusLabel.setText("Scanning " + urls.size() + " URL(s)…");

            int threads = (int) concurrencySpinner.getValue();
            executor = Executors.newFixedThreadPool(threads, r -> {
                Thread t = new Thread(r, "SecretSifter-Bulk");
                t.setDaemon(true);
                return t;
            });

            for (String url : urls) {
                executor.submit(() -> {
                    if (!running.get()) return;
                    try {
                        int timeoutSecs = settings.getUrlTimeoutSeconds();
                        if (timeoutSecs > 0) {
                            ExecutorService urlExec = Executors.newSingleThreadExecutor(r -> {
                                Thread t = new Thread(r, "SecretSifter-URL");
                                t.setDaemon(true);
                                return t;
                            });
                            Future<?> f = urlExec.submit(() -> processUrl(url));
                            urlExec.shutdown();
                            try {
                                f.get(timeoutSecs, TimeUnit.SECONDS);
                            } catch (TimeoutException te) {
                                f.cancel(true);
                                recordTargetStatus(url, "\u23f1", "Timed out (>" + timeoutSecs + "s)");
                                logger.logToError("URL timed out (>" + timeoutSecs + "s): " + url);
                            } catch (ExecutionException ee) {
                                logger.logToError("BulkScanPanel.processUrl(" + url + "): " + ee.getCause());
                            } catch (InterruptedException ie) {
                                f.cancel(true);
                                Thread.currentThread().interrupt();
                            }
                        } else {
                            processUrl(url);
                        }
                    } catch (Exception e) {
                        logger.logToError("BulkScanPanel.processUrl(" + url + "): " + e.getMessage());
                    } finally {
                        int done  = urlsDone.incrementAndGet();
                        int total = urls.size();
                        SwingUtilities.invokeLater(() -> {
                            if (progressBar.isIndeterminate()) {
                                progressBar.setIndeterminate(false);
                                progressBar.setMinimum(0);
                                progressBar.setMaximum(total);
                            }
                            progressBar.setValue(done);
                            progressBar.setString(done + " / " + total);
                            if (done >= total) onScanComplete(total);
                        });
                    }
                });
            }
            executor.shutdown();
        }
    }

    // =========================================================================
    // Browser scan (Playwright)
    // =========================================================================

    private void startBrowserScan(List<String> urls) {
        progressBar.setIndeterminate(true);
        progressBar.setString("Checking targets…");
        statusLabel.setText("Browser mode: checking liveness of " + urls.size() + " seed URL(s)…");

        // Build host→seed map up front so the consumer can attribute each resource.
        Map<String, String> hostToSeed = new java.util.LinkedHashMap<>();
        for (String seedUrl : urls) {
            String norm = normaliseUrl(seedUrl);
            if (norm == null) continue;
            try { hostToSeed.put(new java.net.URL(norm).getHost(), norm); }
            catch (Exception ignored) {}
        }

        // Shared queue — crawler produces JsResult items; consumer scans them in parallel.
        // END_SENTINEL is always placed by the crawler when it finishes (even on error).
        java.util.concurrent.LinkedBlockingQueue<PlaywrightCrawler.JsResult> queue =
                new java.util.concurrent.LinkedBlockingQueue<>();

        // Two named threads: one for Playwright crawl, one for scanning.
        java.util.concurrent.atomic.AtomicInteger threadIdx = new java.util.concurrent.atomic.AtomicInteger();
        executor = Executors.newFixedThreadPool(2, r -> {
            int idx = threadIdx.incrementAndGet();
            Thread t = new Thread(r, idx == 1 ? "SS-Crawler" : "SS-Scanner");
            t.setDaemon(true);
            return t;
        });

        // ── Crawler task ──────────────────────────────────────────────────────
        executor.submit(() -> {
            try {
                // Liveness pre-check — HTTP probe before browser launches
                SwingUtilities.invokeLater(() -> {
                    progressBar.setString("Checking targets…");
                    statusLabel.setText("Checking liveness of " + urls.size() + " seed URL(s)…");
                });
                for (String seedUrl : urls) {
                    if (!running.get()) break;
                    String norm = normaliseUrl(seedUrl);
                    if (norm == null) continue;
                    final String displayNorm = norm;
                    SwingUtilities.invokeLater(() -> currentFileLabel.setText("↳ " + displayNorm));
                    HttpFetcher.FetchResult probe = fetcher.fetchUrl(norm);
                    if (probe == null) {
                        statusFailed.incrementAndGet();
                        recordTargetStatus(norm, "❌", "Unreachable");
                    } else {
                        int sc = probe.statusCode();
                        if (sc == 401 || sc == 403) {
                            statusAuth.incrementAndGet();
                            recordTargetStatus(norm, "🔒", "Auth (" + sc + ")");
                        } else if (sc >= 200 && sc < 400) {
                            statusScanned.incrementAndGet();
                            recordTargetStatus(norm, "✅", "HTTP " + sc);
                        } else {
                            statusFailed.incrementAndGet();
                            recordTargetStatus(norm, "❌", "HTTP " + sc);
                        }
                    }
                }
                if (!running.get()) return;

                SwingUtilities.invokeLater(() -> {
                    progressBar.setString("Crawling…");
                    statusLabel.setText("Browser mode: crawling " + urls.size() + " seed URL(s)…");
                });

                // ── Auto-install Chromium on first use ────────────────────────
                if (!ChromiumInstaller.isInstalled()) {
                    String edgePath = ChromiumInstaller.findSystemEdge();
                    if (edgePath == null) {
                        SwingUtilities.invokeLater(() -> {
                            progressBar.setString("Downloading Chromium…");
                            statusLabel.setText("First-time setup: downloading Chromium (~120 MB)…");
                        });
                        int exitCode = ChromiumInstaller.install(running, line -> SwingUtilities.invokeLater(() -> {
                            statusLabel.setText(line);
                            progressBar.setString(line);
                            java.util.regex.Matcher m =
                                    java.util.regex.Pattern.compile("(\\d+)%").matcher(line);
                            if (m.find()) {
                                int pct = Integer.parseInt(m.group(1));
                                progressBar.setIndeterminate(false);
                                progressBar.setMinimum(0);
                                progressBar.setMaximum(100);
                                progressBar.setValue(pct);
                            }
                        }));
                        if (exitCode != 0 || !running.get()) {
                            SwingUtilities.invokeLater(() -> {
                                progressBar.setIndeterminate(false);
                                if (!running.get()) return;
                                JOptionPane.showMessageDialog(rootPanel,
                                        "Chromium installation failed.\n\n" +
                                        "Install it once by running in a terminal:\n" +
                                        "  java -cp secretsifter.jar com.microsoft.playwright.CLI install chromium\n\n" +
                                        "Or set a custom Chromium path in Settings → Browser Mode.",
                                        "Browser Not Installed", JOptionPane.ERROR_MESSAGE);
                            });
                            return;  // sentinel placed in finally below
                        }
                        SwingUtilities.invokeLater(() -> {
                            progressBar.setString("Crawling…");
                            statusLabel.setText("Chromium installed. Launching browser crawl…");
                        });
                    }
                }

                PlaywrightCrawler crawler = new PlaywrightCrawler(settings, logger);
                crawler.setCaptureStore(captureStore);
                crawler.crawl(urls, running, jsDiscovered, jsFetched, queue);
                // crawl() puts END_SENTINEL itself in its own finally block

            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                logger.logToError("Browser crawl error: " + msg);
                SwingUtilities.invokeLater(() -> {
                    if (msg.contains("TargetClosed") && jsFetched.get() > 0) return;
                    if (msg.contains("xecutable") || msg.contains("not found") ||
                        msg.contains("install")   || msg.contains("driver")) {
                        JOptionPane.showMessageDialog(rootPanel,
                                "Browser not found.\n\n" +
                                "Install Chromium by running in a terminal:\n" +
                                "  java -cp secretsifter.jar com.microsoft.playwright.CLI install chromium\n\n" +
                                "Or set a custom browser path in Settings → Browser Mode.",
                                "Browser Not Installed", JOptionPane.ERROR_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(rootPanel,
                                "Browser scan failed:\n" + msg,
                                "Browser Error", JOptionPane.ERROR_MESSAGE);
                    }
                });
                // Ensure consumer is unblocked even if crawl() never ran
                queue.offer(PlaywrightCrawler.END_SENTINEL);
            }
        });

        // ── Consumer task ─────────────────────────────────────────────────────
        executor.submit(() -> {
            AtomicInteger scanDone = new AtomicInteger(0);
            Set<String> crawledHosts = ConcurrentHashMap.newKeySet();
            try {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(true);
                    progressBar.setString("Scanning…");
                });

                while (running.get()) {
                    // ── Pause support ─────────────────────────────────────────
                    if (paused.get()) {
                        Thread.sleep(200);
                        continue;
                    }

                    PlaywrightCrawler.JsResult item =
                            queue.poll(500, java.util.concurrent.TimeUnit.MILLISECONDS);
                    if (item == null) continue;          // timeout — loop to check running/paused
                    if (item == PlaywrightCrawler.END_SENTINEL) break;  // crawl finished

                    // Track which hosts produced resources (for status update later)
                    try { crawledHosts.add(new java.net.URL(item.url()).getHost()); }
                    catch (Exception ignored) {}

                    final int fileNum = scanDone.incrementAndGet();
                    final String jsUrl      = item.url();
                    final String seedTarget = item.targetUrl() != null ? item.targetUrl() : "";

                    logger.logToOutput("[Scanner] " + item.contentType() +
                            " #" + fileNum + ": " + jsUrl);
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Crawling + scanning… (" + fileNum + " file(s) done)");
                        currentFileLabel.setText("↳ " + jsUrl);
                        progressBar.setString(fileNum + " files scanned");
                    });

                    scanAndAppend(item.body(), item.contentType(), jsUrl, seedTarget);
                }

            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } finally {
                // Update status rows with crawl outcome
                for (String seedUrl : urls) {
                    String norm = normaliseUrl(seedUrl);
                    if (norm == null) continue;
                    String host = null;
                    try { host = new java.net.URL(norm).getHost(); } catch (Exception ignored) {}
                    if (host != null && crawledHosts.contains(host)) {
                        updateTargetStatusDetail(norm, "+ Crawled");
                    } else {
                        updateTargetStatusDetail(norm, "+ No resources");
                    }
                }
                final int total = scanDone.get();
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    onScanComplete(total);
                });
            }
        });

        executor.shutdown();
    }

    private void onBrowserModeToggled() {
        boolean on = browserModeBox.isSelected();
        followScriptSrcBox.setEnabled(!on);
        followChunksBox.setEnabled(!on);
        concurrencySpinner.setEnabled(!on);
    }

    public void stopScan() {
        paused.set(false);
        running.set(false);
        if (executor != null) executor.shutdownNow();
        onScanComplete(-1);
    }

    public void pauseScan() {
        if (running.get() && !paused.get()) SwingUtilities.invokeLater(this::togglePause);
    }

    public void resumeScan() {
        if (running.get() && paused.get()) SwingUtilities.invokeLater(this::togglePause);
    }

    /**
     * Programmatic scan start — called by MCP tools without showing file-chooser dialogs.
     * Safe to call from any thread; hands off to the EDT.
     */
    public void startScanProgrammatic(List<String> urls, int threads,
                                       boolean browserMode, boolean followScripts,
                                       boolean followChunks, boolean crossOriginApis,
                                       boolean strictScope) {
        if (running.get()) return;
        SwingUtilities.invokeLater(() -> {
            urlArea.setText(String.join("\n", urls));
            concurrencySpinner.setValue(Math.max(1, Math.min(50, threads)));
            browserModeBox.setSelected(browserMode);
            followScriptSrcBox.setSelected(followScripts);
            followChunksBox.setSelected(followChunks);
            crossOriginApisBox.setSelected(crossOriginApis);
            settings.setFollowCrossOriginApis(crossOriginApis);
            strictScopeBox.setSelected(strictScope);
            settings.setStrictScope(strictScope);
            startScan();
        });
    }

    /** Returns a JSON snapshot of current scan state — safe to call from any thread. */
    public org.json.JSONObject getScanStatus() {
        return new org.json.JSONObject()
                .put("running",        running.get())
                .put("paused",         paused.get())
                .put("urlsDone",       urlsDone.get())
                .put("findings",       tableFindings.size())
                .put("jsFetched",      jsFetched.get())
                .put("statusScanned",  statusScanned.get())
                .put("statusFailed",   statusFailed.get())
                .put("statusAuth",     statusAuth.get());
    }

    /**
     * Update severity and/or confidence of a finding by model-row index.
     * Pass null for either field to leave it unchanged.
     */
    public boolean updateFinding(int modelIndex, String severity, String confidence) {
        synchronized (tableFindings) {
            if (modelIndex < 0 || modelIndex >= tableFindings.size()) return false;
            SecretFinding old = tableFindings.get(modelIndex);
            String newSev  = (severity   != null && !severity.isBlank())   ? severity.toUpperCase()   : old.severity();
            String newConf = (confidence != null && !confidence.isBlank()) ? confidence.toUpperCase() : old.confidence();
            tableFindings.set(modelIndex, old.withSeverity(newSev).withConfidence(newConf));
            SwingUtilities.invokeLater(() -> {
                if (modelIndex < tableModel.getRowCount()) {
                    tableModel.setValueAt(newSev,  modelIndex, COL_SEV);
                    tableModel.setValueAt(newConf, modelIndex, COL_CONF);
                }
            });
            return true;
        }
    }

    /** Delete a finding by model-row index (false positive removal). */
    public boolean deleteFinding(int modelIndex) {
        synchronized (tableFindings) {
            if (modelIndex < 0 || modelIndex >= tableFindings.size()) return false;
            tableFindings.remove(modelIndex);
        }
        SwingUtilities.invokeLater(() -> {
            if (modelIndex < tableModel.getRowCount()) {
                tableModel.removeRow(modelIndex);
            }
        });
        return true;
    }

    /**
     * Export findings to a file without showing any GUI dialogs.
     * format: "csv", "json", or "html". Returns the written file, or null on error.
     */
    public java.io.File exportReport(String format, java.io.File outputFile) {
        List<SecretFinding> snap;
        synchronized (tableFindings) {
            snap = new ArrayList<>(tableFindings);
        }
        if (snap.isEmpty()) return null;
        try {
            String fmt = format.toLowerCase();
            if ("csv".equals(fmt)) {
                try (java.io.PrintWriter pw = new java.io.PrintWriter(
                        new java.io.FileWriter(outputFile, java.nio.charset.StandardCharsets.UTF_8))) {
                    pw.println("Rule ID,Rule Name,Key,Value,Severity,Confidence,Line,URL,Target,Context");
                    for (SecretFinding f : snap) {
                        pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\"%n",
                                csvEsc(f.ruleId()), csvEsc(f.ruleName()),
                                csvEsc(f.keyName()), csvEsc(f.matchedValue()),
                                f.severity(), f.confidence(), f.lineNumber(),
                                csvEsc(f.sourceUrl()),
                                csvEsc(f.targetUrl() != null ? f.targetUrl() : ""),
                                csvEsc(f.context() != null ? f.context().replace("\n", " ") : ""));
                    }
                }
            } else if ("json".equals(fmt)) {
                org.json.JSONArray arr = new org.json.JSONArray();
                for (SecretFinding f : snap) {
                    arr.put(new org.json.JSONObject()
                            .put("ruleId",     f.ruleId())
                            .put("ruleName",   f.ruleName())
                            .put("key",        f.keyName())
                            .put("value",      f.matchedValue())
                            .put("severity",   f.severity())
                            .put("confidence", f.confidence())
                            .put("lineNumber", f.lineNumber())
                            .put("url",        f.sourceUrl())
                            .put("target",     f.targetUrl() != null ? f.targetUrl() : "")
                            .put("context",    f.context() != null ? f.context() : ""));
                }
                try (java.io.PrintWriter pw = new java.io.PrintWriter(
                        new java.io.FileWriter(outputFile, java.nio.charset.StandardCharsets.UTF_8))) {
                    pw.print(arr.toString(2));
                }
            } else if ("html".equals(fmt)) {
                String target = snap.get(0).targetUrl();
                if (target == null || target.isBlank()) target = snap.get(0).sourceUrl();
                String html = HtmlReportGenerator.generate(snap, target, settings.getTier().name());
                try (java.io.FileWriter fw = new java.io.FileWriter(outputFile,
                        java.nio.charset.StandardCharsets.UTF_8)) {
                    fw.write(html);
                }
            } else {
                return null;
            }
            return outputFile;
        } catch (Exception ex) {
            return null;
        }
    }

    /** Programmatic HAR file scan — no dialogs. Starts async background thread. */
    public String importHarFile(java.io.File harFile) {
        if (harFile == null || !harFile.exists())
            return "File not found: " + (harFile == null ? "null" : harFile.getPath());
        new Thread(() -> {
            try {
                String raw;
                try (java.io.InputStream is = new java.io.FileInputStream(harFile)) {
                    raw = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                }
                org.json.JSONObject har     = new org.json.JSONObject(raw);
                org.json.JSONArray  entries = har.getJSONObject("log").getJSONArray("entries");
                int total = entries.length(), scanned = 0;
                for (int i = 0; i < total; i++) {
                    org.json.JSONObject entry    = entries.getJSONObject(i);
                    org.json.JSONObject request  = entry.getJSONObject("request");
                    org.json.JSONObject response = entry.getJSONObject("response");
                    String url    = request.optString("url", "");
                    int    status = response.optInt("status", 0);
                    if (status < 200 || status >= 300) continue;
                    org.json.JSONObject content = response.optJSONObject("content");
                    if (content == null) continue;
                    String mimeType = content.optString("mimeType", "");
                    String body     = content.optString("text", "");
                    if (body.isBlank()) continue;
                    String mt = mimeType.toLowerCase();
                    if (!mt.contains("javascript") && !mt.contains("text/html")
                            && !mt.contains("application/json") && !mt.contains("text/plain")
                            && !mt.contains("application/xml") && !mt.contains("text/xml")) continue;
                    if (settings.isExternalCdn(url)) continue;
                    final String fUrl = url, fMime = mimeType, fBody = body;
                    SwingUtilities.invokeLater(() -> scanAndAppend(fBody, fMime, fUrl, fUrl));
                    scanned++;
                }
                final String msg = "HAR scan complete: " + scanned + " of " + total
                        + " entries scanned from " + harFile.getName();
                logger.logToOutput(msg);
            } catch (Exception ex) {
                logger.logToError("HAR import failed: " + ex.getMessage());
            }
        }, "SecretSifter-HarImportMcp").start();
        return "HAR scan started for " + harFile.getName()
                + " — use get_findings and get_logs to monitor results.";
    }

    private void togglePause() {
        if (paused.compareAndSet(false, true)) {
            pauseBtn.setText("Resume");
            statusLabel.setText("Paused — click Resume to continue scanning…");
            statusLabel.setForeground(Color.ORANGE);
        } else {
            paused.set(false);
            pauseBtn.setText("Pause");
            statusLabel.setForeground(new Color(80, 180, 255));
        }
    }

    // =========================================================================
    // Scan timer
    // =========================================================================

    private void startScanTimer() {
        scanStartMs = System.currentTimeMillis();
        if (scanTimer != null) scanTimer.stop();
        timerLabel.setForeground(new Color(80, 180, 255));
        timerLabel.setText("⏱ 0:00");
        scanTimer = new javax.swing.Timer(1000, e -> {
            long secs = (System.currentTimeMillis() - scanStartMs) / 1000;
            timerLabel.setText(String.format("⏱ %d:%02d", secs / 60, secs % 60));
        });
        scanTimer.start();
    }

    private void stopScanTimer() {
        if (scanTimer != null) {
            scanTimer.stop();
            long secs = (System.currentTimeMillis() - scanStartMs) / 1000;
            timerLabel.setText(String.format("⏱ %d:%02d", secs / 60, secs % 60));
            timerLabel.setForeground(Color.WHITE);
        }
    }

    private void onScanComplete(int total) {
        if (!scanCompleting.compareAndSet(false, true)) return; // already called
        running.set(false);
        paused.set(false);
        progressBar.setIndeterminate(false);
        stopScanTimer();
        currentFileLabel.setText("");
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        pauseBtn.setEnabled(false);
        pauseBtn.setText("Pause");
        int found   = tableFindings.size();
        int disc    = jsDiscovered.get();
        int fetc    = jsFetched.get();
        int skipped = Math.max(0, disc - fetc);
        boolean stopped = (total < 0);

        String msg;
        if (wasBrowserMode) {
            int filesScanned = stopped ? fetc : total;
            msg = String.format("%s  %d finding(s)  ·  %d files scanned  ·  %d duplicate bodies skipped",
                                stopped ? "Stopped." : "Done.", found, filesScanned, skipped);
        } else {
            int seeds = stopped ? urlsDone.get() : total;
            if (disc > 0) {
                msg = String.format("%s  %d finding(s)  ·  %d seed URL(s)  ·  %d JS fetched  (%d duplicate bodies skipped)",
                                    stopped ? "Stopped." : "Done.", found, seeds, fetc, skipped);
            } else {
                msg = String.format("%s  %d finding(s)  ·  %d seed URL(s) processed",
                                    stopped ? "Stopped." : "Done.", found, seeds);
            }
        }
        msg += severitySummary();
        statusLabel.setText(msg);
        statusLabel.setForeground(stopped ? Color.GRAY : new Color(50, 200, 100));
    }

    // =========================================================================
    // Per-URL processing
    // =========================================================================

    private void processUrl(String targetUrl) {
        if (!running.get()) return;
        String normalised = normaliseUrl(targetUrl);
        if (normalised == null) return;

        logger.logToOutput("[Scan] ===== Target: " + normalised + " =====");
        SwingUtilities.invokeLater(() -> currentFileLabel.setText("↳ " + normalised));

        HttpFetcher.FetchResult page = fetcher.fetchUrl(normalised);

        if (page == null) {
            statusFailed.incrementAndGet();
            recordTargetStatus(normalised, "❌", "Unreachable");
            logger.logToOutput("[Scan] Unreachable: " + normalised);
            return;
        }
        int sc = page.statusCode();
        if (sc == 401 || sc == 403) {
            statusAuth.incrementAndGet();
            recordTargetStatus(normalised, "🔒", "Auth (" + sc + ")");
            logger.logToOutput("[Scan] Auth required (HTTP " + sc + "): " + normalised);
            return;
        }
        if (page.body() == null) {
            statusFailed.incrementAndGet();
            recordTargetStatus(normalised, "❌", "HTTP " + sc);
            logger.logToOutput("[Scan] No body (HTTP " + sc + "): " + normalised);
            return;
        }

        statusScanned.incrementAndGet();
        recordTargetStatus(normalised, "✅", "OK");

        String baseUrl = (page.finalUrl() != null && !page.finalUrl().equals(normalised))
                ? page.finalUrl() : normalised;
        String ct = page.contentType() != null ? page.contentType().toLowerCase() : "";
        logger.logToOutput("[Scan] HTTP " + sc + " [" + ct + "]: " + normalised);

        scanAndAppend(page.body(), page.contentType(), baseUrl, normalised);

        if (ct.contains("text/html") || ct.contains("application/xhtml")) {
            Set<String> fetched = new HashSet<>();
            fetched.add(normalised);
            fetched.add(baseUrl);

            if (followScriptSrcBox.isSelected()) {
                String baseHost;
                try { baseHost = new java.net.URL(baseUrl).getHost().toLowerCase(); }
                catch (Exception e) { baseHost = null; }

                List<String> scriptUrls = new ArrayList<>(
                        SecretScanner.extractScriptSrcs(page.body(), baseUrl));
                List<String> preloadUrls = SecretScanner.extractPreloadLinks(page.body(), baseUrl);
                for (String u : preloadUrls) {
                    if (!scriptUrls.contains(u)) scriptUrls.add(u);
                }

                // <frame src> / <iframe src> — frameset apps hide scripts inside child frames
                List<String> frameUrls = new ArrayList<>(
                        SecretScanner.extractFrameSrcs(page.body(), baseUrl));
                if (baseHost != null) {
                    final String fh2 = baseHost;
                    frameUrls.removeIf(u -> {
                        try { return !new java.net.URL(u).getHost().toLowerCase().equals(fh2); }
                        catch (Exception ignored) { return true; }
                    });
                }
                if (!frameUrls.isEmpty())
                    logger.logToOutput("[Scan] Found " + frameUrls.size() + " frame(s) in: " + baseUrl);
                for (String frameUrl : frameUrls) {
                    if (!running.get()) break;
                    if (!fetched.add(frameUrl)) continue;
                    logger.logToOutput("[Scan] Fetching frame: " + frameUrl);
                    HttpFetcher.FetchResult fr = fetcher.fetchUrl(frameUrl);
                    if (fr == null || fr.body() == null) continue;
                    scanAndAppend(fr.body(), "text/html", frameUrl, normalised);
                    for (String u : SecretScanner.extractScriptSrcs(fr.body(), frameUrl)) {
                        try { if (baseHost != null && !new java.net.URL(u).getHost().toLowerCase().equals(baseHost)) continue; } catch (Exception ignored) { continue; }
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    for (String u : SecretScanner.extractPreloadLinks(fr.body(), frameUrl)) {
                        try { if (baseHost != null && !new java.net.URL(u).getHost().toLowerCase().equals(baseHost)) continue; } catch (Exception ignored) { continue; }
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    // Nested frames (one level deep)
                    for (String u : SecretScanner.extractFrameSrcs(fr.body(), frameUrl)) {
                        try { if (baseHost != null && !new java.net.URL(u).getHost().toLowerCase().equals(baseHost)) continue; } catch (Exception ignored) { continue; }
                        if (!fetched.add(u)) continue;
                        HttpFetcher.FetchResult nfr = fetcher.fetchUrl(u);
                        if (nfr == null || nfr.body() == null) continue;
                        scanAndAppend(nfr.body(), "text/html", u, normalised);
                        for (String s : SecretScanner.extractScriptSrcs(nfr.body(), u)) {
                            if (!scriptUrls.contains(s)) scriptUrls.add(s);
                        }
                    }
                }

                // JS window.location / meta-refresh redirects
                List<String> redirectUrls = new ArrayList<>(
                        SecretScanner.extractJsRedirects(page.body(), baseUrl));
                if (baseHost != null) {
                    final String fhR = baseHost;
                    redirectUrls.removeIf(u -> {
                        try { return !new java.net.URL(u).getHost().toLowerCase().equals(fhR); }
                        catch (Exception ignored) { return true; }
                    });
                }
                if (!redirectUrls.isEmpty())
                    logger.logToOutput("[Scan] Found " + redirectUrls.size() + " JS redirect(s) in: " + baseUrl);
                for (String redirectUrl : redirectUrls) {
                    if (!running.get()) break;
                    if (!fetched.add(redirectUrl)) continue;
                    logger.logToOutput("[Scan] Following JS redirect: " + redirectUrl);
                    HttpFetcher.FetchResult rr = fetcher.fetchUrl(redirectUrl);
                    if (rr == null || rr.body() == null) continue;
                    scanAndAppend(rr.body(), "text/html", redirectUrl, normalised);
                    for (String u : SecretScanner.extractScriptSrcs(rr.body(), redirectUrl)) {
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    for (String u : SecretScanner.extractPreloadLinks(rr.body(), redirectUrl)) {
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    for (String frameUrl : SecretScanner.extractFrameSrcs(rr.body(), redirectUrl)) {
                        try { if (baseHost != null && !new java.net.URL(frameUrl).getHost().toLowerCase().equals(baseHost)) continue; } catch (Exception ignored) { continue; }
                        if (!fetched.add(frameUrl)) continue;
                        HttpFetcher.FetchResult fr2 = fetcher.fetchUrl(frameUrl);
                        if (fr2 == null || fr2.body() == null) continue;
                        scanAndAppend(fr2.body(), "text/html", frameUrl, normalised);
                        for (String s : SecretScanner.extractScriptSrcs(fr2.body(), frameUrl)) {
                            if (!scriptUrls.contains(s)) scriptUrls.add(s);
                        }
                    }
                }

                // Script host filter: cross-origin mode allows all non-CDN; default = same host
                if (settings.isFollowCrossOriginApis()) {
                    scriptUrls.removeIf(u -> settings.isExternalCdn(u));
                } else {
                    if (baseHost != null) {
                        final String fh = baseHost;
                        scriptUrls.removeIf(u -> {
                            try { return !new java.net.URL(u).getHost().toLowerCase().equals(fh); }
                            catch (Exception ignored) { return true; }
                        });
                    }
                }

                logger.logToOutput("[Scan] Found " + scriptUrls.size() + " script(s) to fetch from: " + baseUrl);
                jsDiscovered.addAndGet(scriptUrls.size());

                for (String jsUrl : scriptUrls) {
                    if (!running.get()) return;
                    if (!fetched.add(jsUrl)) continue;
                    logger.logToOutput("[Scan] Fetching script: " + jsUrl);
                    final String ju = jsUrl;
                    SwingUtilities.invokeLater(() -> currentFileLabel.setText("↳ " + ju));
                    HttpFetcher.FetchResult js = fetcher.fetchUrl(jsUrl);
                    if (js == null || js.body() == null) {
                        logger.logToOutput("[Scan] Script unreachable: " + jsUrl);
                        continue;
                    }
                    jsFetched.incrementAndGet();
                    logger.logToOutput("[Scan] Fetched " + js.body().length() + " bytes: " + jsUrl);
                    scanAndAppend(js.body(), "application/javascript", jsUrl, normalised);

                    if (followChunksBox.isSelected()) {
                        List<String> chunkUrls = SecretScanner.extractWebpackChunkUrls(js.body(), jsUrl);
                        if (!chunkUrls.isEmpty())
                            logger.logToOutput("[Scan] Found " + chunkUrls.size() + " chunk(s) in: " + jsUrl);
                        jsDiscovered.addAndGet(chunkUrls.size());
                        for (String chunkUrl : chunkUrls) {
                            if (!running.get()) return;
                            if (!fetched.add(chunkUrl)) continue;
                            HttpFetcher.FetchResult chunk = fetcher.fetchUrl(chunkUrl);
                            if (chunk == null || chunk.body() == null) continue;
                            jsFetched.incrementAndGet();
                            scanAndAppend(chunk.body(), "application/javascript", chunkUrl, normalised);
                        }
                    }
                }

                if (followChunksBox.isSelected()) {
                    followAssetManifests(baseUrl, fetched, normalised);
                }
            }
        }

        logger.logToOutput("[Scan] Done: " + normalised);
    }

    private void followAssetManifests(String baseUrl, Set<String> fetched, String targetUrl) {
        String origin;
        try {
            java.net.URL u = new java.net.URL(baseUrl);
            origin = u.getProtocol() + "://" + u.getHost() +
                     (u.getPort() > 0 && u.getPort() != 80 && u.getPort() != 443
                             ? ":" + u.getPort() : "");
        } catch (Exception e) { return; }

        String[] manifestPaths = {
            "/asset-manifest.json", "/static/js/manifest.json",
            "/chunk-manifest.json", "/webpack-manifest.json"
        };

        for (String path : manifestPaths) {
            if (!running.get()) return;
            String manifestUrl = origin + path;
            if (!fetched.add(manifestUrl)) continue;
            HttpFetcher.FetchResult mf = fetcher.fetchUrl(manifestUrl);
            if (mf == null || mf.body() == null) continue;

            List<String> chunkUrls = SecretScanner.extractAssetManifestUrls(mf.body(), baseUrl);
            jsDiscovered.addAndGet(chunkUrls.size());
            for (String chunkUrl : chunkUrls) {
                if (!running.get()) return;
                if (!fetched.add(chunkUrl)) continue;
                HttpFetcher.FetchResult chunk = fetcher.fetchUrl(chunkUrl);
                if (chunk == null || chunk.body() == null) continue;
                jsFetched.incrementAndGet();
                scanAndAppend(chunk.body(), "application/javascript", chunkUrl, targetUrl);
            }
        }
    }

    // =========================================================================
    // Scan + append
    // =========================================================================

    /**
     * Scans {@code body} for secrets and appends each finding to the results table.
     * URL-based dedup: same URL is never scanned twice in one session.
     * @param targetUrl the seed URL entered by the user (shown in Target column)
     */
    private void scanAndAppend(String body, String contentType, String url, String targetUrl) {
        if (body == null || body.isBlank()) return;
        if (!seenUrls.add(url != null ? url : "")) return;
        String labelledUrl = sourceLabel(url, contentType);
        // Record this body in CaptureStore.  The "url" passed here may carry a
        // [REQ-HEADERS] or [REQ-BODY] tag — strip it so the merge folds into the
        // single canonical capture for this raw URL (which may already hold the
        // response from PlaywrightCrawler.onResponse, or vice versa).
        if (url != null && !url.isBlank()) {
            String rawUrl = url;
            String reqHdrs = null, reqBody = null, respBody = null;
            if (url.endsWith(" [REQ-HEADERS]")) {
                rawUrl  = url.substring(0, url.length() - " [REQ-HEADERS]".length());
                reqHdrs = body;
            } else if (url.endsWith(" [REQ-BODY]")) {
                rawUrl  = url.substring(0, url.length() - " [REQ-BODY]".length());
                reqBody = body;
            } else {
                respBody = body;
            }
            captureStore.merge(rawUrl, reqHdrs, reqBody, respBody, contentType,
                               0, null, null, null);
        }
        String tgt = targetUrl != null ? targetUrl : "";
        List<SecretFinding> findings = scanner.scanText(body, contentType, labelledUrl);
        for (SecretFinding f : findings) {
            SecretFinding withTarget = f.withTargetUrl(tgt);
            SwingUtilities.invokeLater(() -> appendFinding(withTarget));
        }
    }

    /** Called by ProxyPanel to inject pre-scanned findings (proxy mode). */
    public void addFindings(List<SecretFinding> findings) {
        for (SecretFinding f : findings)
            SwingUtilities.invokeLater(() -> appendFinding(f));
    }

    /** CaptureStore for the Details side-panel. Shared so proxy/HAR/crawler all write here. */
    public CaptureStore getCaptureStore() { return captureStore; }

    // =========================================================================
    // Details side panel — Details / Request / Response tabs
    // =========================================================================

    private JPanel buildDetailsPanel() {
        JPanel panel = new JPanel(new BorderLayout(2, 2));
        panel.setBorder(BorderFactory.createTitledBorder("Finding Details"));

        detailsTitle = new JLabel(" Select a finding to view details");
        detailsTitle.setFont(SecretSifterApp.UI_BOLD_13);
        detailsTitle.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        detailsTitle.setForeground(new Color(180, 180, 180));

        // Severity / Confidence combos — placed inside the Details tab body, NOT above
        // the tabs.  Keeping the toolbar slim above the tabs gives the findings table
        // back the vertical space it lost in the previous iteration.
        detailsSevCombo  = new JComboBox<>(
                new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION", "NOISE"});
        detailsSevCombo.setFont(SecretSifterApp.UI_BOLD_11);
        detailsSevCombo.setToolTipText(
                "Change severity for this finding.  Selecting NOISE greys out the row " +
                "and excludes it from HTML / CSV / JSON exports.");
        detailsSevCombo.addActionListener(e -> {
            if (detailsSyncing || currentDetailsModelRow < 0) return;
            String v = (String) detailsSevCombo.getSelectedItem();
            if (v == null) return;
            tableModel.setValueAt(v, currentDetailsModelRow, COL_SEV);
        });

        detailsConfCombo = new JComboBox<>(
                new String[]{"CERTAIN", "FIRM", "TENTATIVE", "NOISE"});
        detailsConfCombo.setFont(SecretSifterApp.UI_PLAIN_11);
        detailsConfCombo.setToolTipText("Change confidence for this finding");
        detailsConfCombo.addActionListener(e -> {
            if (detailsSyncing || currentDetailsModelRow < 0) return;
            String v = (String) detailsConfCombo.getSelectedItem();
            if (v == null) return;
            tableModel.setValueAt(v, currentDetailsModelRow, COL_CONF);
        });

        // ── Tabs ───────────────────────────────────────────────────────────
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(SecretSifterApp.UI_BOLD_11);

        tabs.addTab("Details", buildDetailsTabContent());

        // Request tab with search bar
        requestPane = new JTextArea();
        requestPane.setEditable(false);
        requestPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        requestPane.setLineWrap(true);
        requestPane.setWrapStyleWord(false);
        requestSearch = new JTextField();
        tabs.addTab("Request", buildSearchablePane(requestPane, requestSearch));

        // Response tab with search bar
        responsePane = new JTextArea();
        responsePane.setEditable(false);
        responsePane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        responsePane.setLineWrap(true);
        responsePane.setWrapStyleWord(false);
        responseSearch = new JTextField();
        tabs.addTab("Response", buildSearchablePane(responsePane, responseSearch));

        panel.add(detailsTitle, BorderLayout.NORTH);
        panel.add(tabs,         BorderLayout.CENTER);
        return panel;
    }

    /** Build the Details tab body — combo controls + form fields with inline copy
     *  buttons next to each URL and the matched value.  Replaces the old HTML pane. */
    private JComponent buildDetailsTabContent() {
        // Read-only fields populated by updateDetailsPanel
        detailsRuleIdField    = roField();
        detailsRuleNameField  = roField();
        detailsKeyField       = roField();
        detailsLineField      = roField();
        detailsSourceUrlField = roField();
        detailsTargetUrlField = roField();

        detailsValueArea   = roTextArea();
        detailsValueArea.setForeground(new Color(255, 210, 122));
        detailsContextArea = roTextArea();

        JButton copySrcBtn = compactCopyBtn("source");
        JButton copyTgtBtn = compactCopyBtn("target");
        JButton copyValBtn = compactCopyBtn("value");

        // Severity / Confidence row
        JPanel sevRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        sevRow.add(new JLabel("Severity:"));
        sevRow.add(detailsSevCombo);
        sevRow.add(Box.createHorizontalStrut(8));
        sevRow.add(new JLabel("Confidence:"));
        sevRow.add(detailsConfCombo);

        // Form fields with copy buttons next to URL/value rows
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets   = new Insets(3, 6, 3, 6);
        g.anchor   = GridBagConstraints.WEST;
        g.fill     = GridBagConstraints.HORIZONTAL;
        g.gridy    = 0;
        addFormRow(form, g, "Rule ID:",    detailsRuleIdField,    null);
        addFormRow(form, g, "Rule Name:",  detailsRuleNameField,  null);
        addFormRow(form, g, "Key:",        detailsKeyField,       null);
        addFormRow(form, g, "Line:",       detailsLineField,      null);
        addFormRow(form, g, "Source URL:", detailsSourceUrlField, copySrcBtn);
        addFormRow(form, g, "Target URL:", detailsTargetUrlField, copyTgtBtn);

        // Matched Value pane (wrap text + Copy button on the right)
        JScrollPane valueScroll = new JScrollPane(detailsValueArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        valueScroll.setPreferredSize(new Dimension(300, 60));
        JPanel valueRow = new JPanel(new BorderLayout(4, 0));
        valueRow.add(valueScroll, BorderLayout.CENTER);
        valueRow.add(copyValBtn,  BorderLayout.EAST);
        JPanel valueWrap = new JPanel(new BorderLayout());
        valueWrap.setBorder(new TitledBorder("Matched Value"));
        valueWrap.add(valueRow, BorderLayout.CENTER);

        // Context pane (wrap text)
        JScrollPane ctxScroll = new JScrollPane(detailsContextArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        ctxScroll.setPreferredSize(new Dimension(300, 80));
        JPanel ctxWrap = new JPanel(new BorderLayout());
        ctxWrap.setBorder(new TitledBorder("Context"));
        ctxWrap.add(ctxScroll, BorderLayout.CENTER);

        // Stack vertically: sev row → form → value → context
        JPanel stack = new JPanel();
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        sevRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.setAlignmentX(Component.LEFT_ALIGNMENT);
        valueWrap.setAlignmentX(Component.LEFT_ALIGNMENT);
        ctxWrap.setAlignmentX(Component.LEFT_ALIGNMENT);
        stack.add(sevRow);
        stack.add(form);
        stack.add(valueWrap);
        stack.add(ctxWrap);

        // Both vertical AND horizontal scroll on demand so the form auto-fits its
        // natural preferred size and overflow becomes scrollable rather than clipped.
        // (Long source / target URLs and matched values frequently exceed the
        // configured side-panel width — without horizontal scroll they're hidden.)
        return new JScrollPane(stack,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
    }

    private static JTextField roField() {
        JTextField f = new JTextField();
        f.setEditable(false);
        f.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        return f;
    }

    private static JTextArea roTextArea() {
        JTextArea a = new JTextArea(2, 30);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(false);   // wrap mid-token so long secrets/contexts fit
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        return a;
    }

    private JButton compactCopyBtn(String which) {
        // Tiny clipboard glyph (📋 Unicode CLIPBOARD) saves horizontal space versus
        // the previous "Copy" text label so the Source / Target URL rows fit cleanly
        // even when the Details side-panel is narrow.
        JButton b = new JButton("📋");
        b.setFont(b.getFont().deriveFont(Font.PLAIN, 12f));
        b.setMargin(new Insets(0, 4, 0, 4));
        b.setPreferredSize(new Dimension(26, 22));
        b.setFocusPainted(false);
        b.setToolTipText("Copy " + which + " to clipboard");
        b.addActionListener(e -> copyCurrentField(which));
        return b;
    }

    private static void addFormRow(JPanel form, GridBagConstraints g,
                                    String label, JComponent field, JComponent rightSide) {
        g.gridx   = 0;
        g.weightx = 0;
        form.add(new JLabel(label), g);
        g.gridx   = 1;
        g.weightx = 1;
        form.add(field, g);
        if (rightSide != null) {
            g.gridx   = 2;
            g.weightx = 0;
            form.add(rightSide, g);
        }
        g.gridy++;
    }

    /** Wrap a text area in a panel with a Burp-style "Search:" toolbar that highlights
     *  matches as the user types and walks through them on Enter / Find Next.
     *  Search execution is debounced 300 ms so typing in a 1-MB response doesn't
     *  re-walk the entire haystack on every keystroke. */
    private static JPanel buildSearchablePane(JTextArea pane, JTextField searchField) {
        JPanel wrap = new JPanel(new BorderLayout(2, 2));

        JLabel  lbl  = new JLabel(" Search: ");
        lbl.setFont(SecretSifterApp.UI_BOLD_11);
        searchField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JButton next = new JButton("Find Next");
        JButton prev = new JButton("Prev");
        next.setFont(SecretSifterApp.UI_BOLD_11);
        prev.setFont(SecretSifterApp.UI_BOLD_11);
        JLabel  count = new JLabel("");
        count.setFont(SecretSifterApp.UI_PLAIN_11);
        count.setForeground(new Color(150, 150, 150));

        // Debounced highlight — Swing Timer fires 300 ms after the user stops typing.
        javax.swing.Timer debounce = new javax.swing.Timer(300, evt -> {
            String q = searchField.getText();
            if (q.isEmpty()) {
                pane.getHighlighter().removeAllHighlights();
                count.setText("");
            } else {
                int n = highlightAllMatches(pane, q);
                count.setText(n + " match" + (n == 1 ? "" : "es"));
            }
        });
        debounce.setRepeats(false);

        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate (javax.swing.event.DocumentEvent e) { debounce.restart(); }
            @Override public void removeUpdate (javax.swing.event.DocumentEvent e) { debounce.restart(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { debounce.restart(); }
        });
        // Enter or "Find Next" → run search immediately + jump to next occurrence.
        java.awt.event.ActionListener gotoNext = e -> {
            debounce.stop();
            highlightAllMatches(pane, searchField.getText());
            jumpToNextMatch(pane, searchField.getText(), true);
        };
        java.awt.event.ActionListener gotoPrev = e -> {
            debounce.stop();
            highlightAllMatches(pane, searchField.getText());
            jumpToNextMatch(pane, searchField.getText(), false);
        };
        searchField.addActionListener(gotoNext);
        next.addActionListener(gotoNext);
        prev.addActionListener(gotoPrev);

        JPanel bar = new JPanel(new BorderLayout(4, 0));
        JPanel barLeft = new JPanel(new BorderLayout(2, 0));
        barLeft.add(lbl, BorderLayout.WEST);
        barLeft.add(searchField, BorderLayout.CENTER);
        JPanel barRight = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        barRight.add(prev);
        barRight.add(next);
        barRight.add(count);
        bar.add(barLeft,  BorderLayout.CENTER);
        bar.add(barRight, BorderLayout.EAST);

        wrap.add(bar, BorderLayout.NORTH);
        wrap.add(new JScrollPane(pane), BorderLayout.CENTER);
        return wrap;
    }

    private static int highlightAllMatches(JTextArea pane, String needle) {
        javax.swing.text.Highlighter hl = pane.getHighlighter();
        hl.removeAllHighlights();
        if (needle == null || needle.isEmpty()) return 0;
        // Pull text from the document directly — avoids any subtle differences
        // between JTextArea.getText() and the document offsets used by Highlighter.
        javax.swing.text.Document doc = pane.getDocument();
        int len = doc.getLength();
        if (len == 0) return 0;
        String hay;
        try { hay = doc.getText(0, len); }
        catch (javax.swing.text.BadLocationException e) { return 0; }
        String hayL = hay.toLowerCase();
        String ndlL = needle.toLowerCase();
        javax.swing.text.Highlighter.HighlightPainter painter =
                new javax.swing.text.DefaultHighlighter.DefaultHighlightPainter(new Color(255, 235, 100));
        int idx = 0, count = 0, MAX = 5000;
        while ((idx = hayL.indexOf(ndlL, idx)) >= 0 && count < MAX) {
            count++;     // count every match indexOf finds, regardless of paint outcome
            try { hl.addHighlight(idx, idx + ndlL.length(), painter); }
            catch (javax.swing.text.BadLocationException ignored) {}
            idx += ndlL.length();
        }
        return count;
    }

    private static void jumpToNextMatch(JTextArea pane, String needle, boolean forward) {
        if (needle == null || needle.isEmpty()) return;
        javax.swing.text.Document doc = pane.getDocument();
        int len = doc.getLength();
        if (len == 0) return;
        String hay;
        try { hay = doc.getText(0, len); }
        catch (javax.swing.text.BadLocationException e) { return; }
        String hayL = hay.toLowerCase();
        String ndlL = needle.toLowerCase();
        int caret = pane.getCaretPosition();
        int idx;
        if (forward) {
            idx = hayL.indexOf(ndlL, Math.min(caret, hayL.length()));
            if (idx < 0) idx = hayL.indexOf(ndlL);   // wrap to top
        } else {
            int searchFrom = Math.max(0, caret - 1);
            idx = hayL.lastIndexOf(ndlL, searchFrom);
            if (idx < 0) idx = hayL.lastIndexOf(ndlL);   // wrap to bottom
        }
        if (idx < 0) return;
        try {
            pane.setCaretPosition(idx);
            pane.moveCaretPosition(idx + ndlL.length());
            pane.getCaret().setSelectionVisible(true);
            java.awt.geom.Rectangle2D r = pane.modelToView2D(idx);
            if (r != null) pane.scrollRectToVisible(r.getBounds());
        } catch (Exception ignored) {}
    }

    private void copyCurrentField(String which) {
        if (currentDetailsModelRow < 0) return;
        SecretFinding f;
        synchronized (tableFindings) {
            if (currentDetailsModelRow >= tableFindings.size()) return;
            f = tableFindings.get(currentDetailsModelRow);
        }
        String text = switch (which) {
            case "source" -> f.sourceUrl();
            case "target" -> f.targetUrl();
            case "value"  -> f.matchedValue();
            default       -> null;
        };
        if (text == null) text = "";
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text), null);
        statusLabel.setText("Copied " + which + " to clipboard.");
        statusLabel.setForeground(new Color(80, 180, 100));
    }

    private void updateDetailsPanel(SecretFinding f) {
        if (f == null) {
            detailsTitle.setText(" Select a finding to view details");
            detailsTitle.setForeground(new Color(180, 180, 180));
            if (detailsRuleIdField != null) {
                detailsRuleIdField.setText("");
                detailsRuleNameField.setText("");
                detailsKeyField.setText("");
                detailsLineField.setText("");
                detailsSourceUrlField.setText("");
                detailsTargetUrlField.setText("");
                detailsValueArea.setText("");
                detailsContextArea.setText("");
            }
            requestPane.setText("");
            responsePane.setText("");
            if (requestSearch  != null) { requestSearch.setText("");  requestPane.getHighlighter().removeAllHighlights();  }
            if (responseSearch != null) { responseSearch.setText(""); responsePane.getHighlighter().removeAllHighlights(); }
            if (detailsSevCombo != null) {
                detailsSyncing = true;
                detailsSevCombo.setSelectedItem(null);
                detailsConfCombo.setSelectedItem(null);
                detailsSyncing = false;
            }
            return;
        }
        String title = f.ruleName() != null && !f.ruleName().isBlank() ? f.ruleName() : f.ruleId();
        detailsTitle.setText(" ●  " + title);
        Color sevColor = SEV_BADGE.getOrDefault(f.severity(), new Color(180, 180, 180));
        detailsTitle.setForeground(sevColor);

        // Push severity/confidence into the dropdown controls (without re-firing the
        // ActionListener that would push the same value back into the table).
        if (detailsSevCombo != null) {
            detailsSyncing = true;
            detailsSevCombo.setSelectedItem(f.severity());
            detailsConfCombo.setSelectedItem(f.confidence());
            detailsSyncing = false;
        }

        // Populate the inline form fields
        if (detailsRuleIdField != null) {
            detailsRuleIdField.setText(nullToBlank(f.ruleId()));
            detailsRuleNameField.setText(nullToBlank(f.ruleName()));
            detailsKeyField.setText(nullToBlank(f.keyName()));
            detailsLineField.setText(String.valueOf(f.lineNumber()));
            detailsSourceUrlField.setText(nullToBlank(f.sourceUrl()));
            detailsSourceUrlField.setCaretPosition(0);
            detailsTargetUrlField.setText(nullToBlank(f.targetUrl()));
            detailsTargetUrlField.setCaretPosition(0);
            detailsValueArea.setText(nullToBlank(f.matchedValue()));
            detailsValueArea.setCaretPosition(0);
            detailsContextArea.setText(nullToBlank(f.context()));
            detailsContextArea.setCaretPosition(0);
        }

        // Clear any previous search highlights before rendering new content
        if (requestSearch != null) {
            requestSearch.setText("");
            requestPane.getHighlighter().removeAllHighlights();
        }
        if (responseSearch != null) {
            responseSearch.setText("");
            responsePane.getHighlighter().removeAllHighlights();
        }

        // Request / Response — look up the full HTTP exchange in CaptureStore
        CaptureStore.Capture cap = captureStore.get(f.sourceUrl());
        if (cap == null) {
            requestPane.setText(
                    "No captured request for:\n    " + f.sourceUrl() +
                    "\n\nThis can happen when the finding came from an inline-script,\n" +
                    "an embedded JSON block, or a source scanned before the CaptureStore\n" +
                    "was populated.  The full context is shown on the Details tab.");
            responsePane.setText(
                    "No captured response for:\n    " + f.sourceUrl() +
                    "\n\n(Captures are retained up to 500 URLs; older ones are evicted.)");
            requestPane.setCaretPosition(0);
            responsePane.setCaretPosition(0);
            return;
        }

        // ── Request pane (HTTP wire format, Burp-style) ────────────────────
        StringBuilder req = new StringBuilder();
        String reqUrlStr = cap.url() != null ? cap.url() : "";
        String path = "/", host = null;
        try {
            java.net.URI u = java.net.URI.create(reqUrlStr);
            host = u.getHost();
            path = (u.getRawPath() == null || u.getRawPath().isEmpty()) ? "/" : u.getRawPath();
            if (u.getRawQuery() != null) path += "?" + u.getRawQuery();
        } catch (Exception ignored) {}
        req.append(cap.method() != null ? cap.method() : "GET").append(' ')
           .append(path).append(" HTTP/1.1\n");
        if (host != null && !host.isEmpty() &&
            (cap.requestHeaders() == null || !cap.requestHeaders().toLowerCase().contains("host:"))) {
            req.append("Host: ").append(host).append('\n');
        }
        if (cap.requestHeaders() != null && !cap.requestHeaders().isBlank())
            req.append(cap.requestHeaders());
        else
            req.append("(no request headers were captured for this URL)\n");
        if (cap.requestBody() != null && !cap.requestBody().isBlank()) {
            if (req.charAt(req.length() - 1) != '\n') req.append('\n');
            req.append('\n').append(cap.requestBody());
        }
        requestPane.setText(req.toString());
        requestPane.setCaretPosition(0);

        // ── Response pane (HTTP wire format, Burp-style) ───────────────────
        StringBuilder rsp = new StringBuilder();
        // Status line — use statusText if it already looks like an HTTP status line,
        // otherwise synthesize one from statusCode.
        String statusText = cap.statusText();
        if (statusText != null && statusText.toUpperCase().startsWith("HTTP/")) {
            rsp.append(statusText).append('\n');
        } else if (cap.statusCode() > 0) {
            rsp.append("HTTP/1.1 ").append(cap.statusCode());
            if (statusText != null && !statusText.isBlank()) rsp.append(' ').append(statusText);
            rsp.append('\n');
        } else {
            rsp.append("(no response status was captured — request may have been " +
                       "to a cross-origin host, a binary asset, or a redirect)\n");
        }
        if (cap.responseHeaders() != null && !cap.responseHeaders().isBlank())
            rsp.append(cap.responseHeaders());
        else if (cap.statusCode() > 0)
            rsp.append("(response headers not captured)\n");
        if (cap.responseBody() != null && !cap.responseBody().isBlank()) {
            if (rsp.charAt(rsp.length() - 1) != '\n') rsp.append('\n');
            rsp.append('\n').append(cap.responseBody());
        } else if (cap.statusCode() > 0) {
            if (rsp.charAt(rsp.length() - 1) != '\n') rsp.append('\n');
            rsp.append("\n(response body not captured — body may be binary, empty, " +
                       "or scope-filtered)\n");
        }
        responsePane.setText(rsp.toString());
        responsePane.setCaretPosition(0);

        // Auto-highlight the matched value in both panes so the user can see at a
        // glance where in the request / response the secret appears, without having
        // to type anything into the search bar.
        autoHighlightValue(f);
    }

    /** Highlight the finding's matched value in both Request and Response panes. */
    private void autoHighlightValue(SecretFinding f) {
        if (f == null || f.matchedValue() == null || f.matchedValue().length() < 4) return;
        highlightAllMatches(requestPane,  f.matchedValue());
        highlightAllMatches(responsePane, f.matchedValue());
    }

    private static String nullToBlank(String s) { return s == null ? "" : s; }

    /** True when the finding has been marked as noise on either severity or confidence. */
    private static boolean isNoise(SecretFinding f) {
        if (f == null) return false;
        return "NOISE".equalsIgnoreCase(f.severity()) || "NOISE".equalsIgnoreCase(f.confidence());
    }
    private static boolean isNoise(String sev, String conf) {
        return "NOISE".equalsIgnoreCase(sev) || "NOISE".equalsIgnoreCase(conf);
    }

    private void appendFinding(SecretFinding f) {
        // Persistent dedup across rescans: same rule+value+URL was already reported — skip.
        String dedupKey = f.ruleId() + "|" + f.matchedValue() + "|" + f.sourceUrl();
        if (!seenValueLines.add(dedupKey)) return;
        // Live key validation (opt-in). Offline checks run immediately; network checks
        // run only when the operator has also enabled "Allow live (network) validation".
        if (settings.isValidationEnabled())
            f = ValidationRunner.validate(f, settings, System.currentTimeMillis());
        tableFindings.add(f);
        tableModel.addRow(new Object[]{
                f.issueId(),
                f.severity(),
                f.confidence(),
                validationLabel(f),
                f.ruleId(),
                f.keyName(),
                f.matchedValue(),
                f.sourceUrl(),
                f.targetUrl() != null ? f.targetUrl() : "",
                f.lineNumber(),
                f.context() != null ? f.context().replace("\n", " ").strip() : "",
                ""   // COL_DEL — delete button column
        });
        int lastRow = tableModel.getRowCount() - 1;
        if (lastRow >= 0) {
            resultsTable.scrollRectToVisible(resultsTable.getCellRect(lastRow, 0, true));
        }
        updateCountBadges();
    }

    // =========================================================================
    // Live key validation (opt-in). Mirrors the Burp MCP edition.
    // =========================================================================

    /** Sort key for the Issue ID column: reorders SS-MMDDYY-XXXXXX to YY MMDD XXXXXX so sort is chronological. */
    static String issueIdSortKey(String id) {
        if (id != null && id.length() >= 16 && id.startsWith("SS-") && id.charAt(9) == '-')
            return id.substring(7, 9) + id.substring(3, 7) + id.substring(9);
        return id == null ? "" : id;
    }

    static String validationLabel(SecretFinding f) {
        return switch (f.meta().validation()) {
            case ACTIVE      -> "active";
            case INACTIVE    -> "dead";
            case RESTRICTED  -> "restricted";
            case UNKNOWN     -> "unknown";
            case NOT_CHECKED -> "—";
        };
    }

    /** Validate toggle: run checks over the current findings, or clear their states. */
    private void onValidateToggled() {
        settings.setValidationEnabled(validateBox.isSelected());
        if (validateBox.isSelected()) runValidationOnFindings();
        else clearValidationStates();
    }

    private void runValidationOnFindings() {
        long now = System.currentTimeMillis();
        int n;
        synchronized (tableFindings) {
            n = Math.min(tableFindings.size(), tableModel.getRowCount());
            for (int i = 0; i < n; i++) {
                SecretFinding updated = ValidationRunner.validate(tableFindings.get(i), settings, now);
                tableFindings.set(i, updated);
                tableModel.setValueAt(validationLabel(updated), i, COL_VALID);
            }
        }
        tableModel.fireTableDataChanged();
        if (statusLabel != null) statusLabel.setText("Validation applied to " + n + " finding(s).");
    }

    private void clearValidationStates() {
        synchronized (tableFindings) {
            int n = Math.min(tableFindings.size(), tableModel.getRowCount());
            for (int i = 0; i < n; i++) {
                SecretFinding f = tableFindings.get(i);
                tableFindings.set(i, f.withMeta(
                        f.meta().withValidation(com.secretsifter.core.FindingMeta.Validation.NOT_CHECKED)));
                tableModel.setValueAt("—", i, COL_VALID);
            }
        }
        tableModel.fireTableDataChanged();
    }

    private static String sourceLabel(String url, String contentType) {
        if (url == null) return "";
        if (url.contains(" [REQ-")) return url;
        String ct = contentType != null ? contentType.toLowerCase() : "";
        if (ct.contains("text/html")        || ct.contains("application/xhtml")) return url + " [HTML]";
        if (ct.contains("javascript")       || ct.contains("ecmascript"))        return url + " [JS]";
        if (ct.contains("application/json") || ct.contains("+json"))             return url + " [JSON]";
        if (ct.contains("text/xml")         || ct.contains("application/xml")
                                            || ct.contains("+xml"))              return url + " [XML]";
        return url;
    }

    // =========================================================================
    // Target status tracking
    // =========================================================================

    private void recordTargetStatus(String url, String icon, String detail) {
        String display;
        try { display = new java.net.URL(url).getHost(); }
        catch (Exception e) { display = url.length() > 50 ? url.substring(0, 50) + "…" : url; }
        String d = display;
        SwingUtilities.invokeLater(() -> {
            targetStatusModel.addRow(new Object[]{icon, d, detail});
            updateSummaryBar();
        });
    }

    /** Appends {@code suffix} to the Detail column of the existing row for {@code url}.
     *  Used by browser mode to add crawl outcome after the liveness pre-check row. */
    private void updateTargetStatusDetail(String url, String suffix) {
        String display;
        try { display = new java.net.URL(url).getHost(); }
        catch (Exception e) { display = url.length() > 50 ? url.substring(0, 50) + "…" : url; }
        String d = display;
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < targetStatusModel.getRowCount(); i++) {
                if (d.equals(targetStatusModel.getValueAt(i, 1))) {
                    Object existing = targetStatusModel.getValueAt(i, 2);
                    targetStatusModel.setValueAt(
                            (existing != null ? existing.toString() : "") + " " + suffix, i, 2);
                    return;
                }
            }
            // Fallback: no pre-check row found — add new row
            targetStatusModel.addRow(new Object[]{"✅", d, suffix.replace("+ ", "")});
            updateSummaryBar();
        });
    }

    private void updateSummaryBar() {
        if (sumScannedLbl == null) return;
        sumScannedLbl.setText("✅  Scanned: " + statusScanned.get());
        sumFailedLbl .setText("❌  Failed: "  + statusFailed.get());
        sumAuthLbl   .setText("🔒  Auth: "    + statusAuth.get());
    }

    private void updateCountBadges() {
        int c = 0, h = 0, m = 0, l = 0, i = 0;
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            Object sev = tableModel.getValueAt(r, COL_SEV);
            if (sev == null) continue;
            switch (sev.toString().toUpperCase()) {
                case "CRITICAL"               -> c++;
                case "HIGH"                   -> h++;
                case "MEDIUM"                 -> m++;
                case "LOW"                    -> l++;
                case "INFORMATION", "INFO"    -> i++;
            }
        }
        critCountLbl.setText("Critical: " + c);
        highCountLbl.setText("High: "     + h);
        medCountLbl.setText("Medium: "    + m);
        lowCountLbl.setText("Low: "       + l);
        infoCountLbl.setText("Info: "     + i);
    }

    /** Returns a numeric rank for severity used by the row sorter and severity filter. */
    private static int sevRank(String sev) {
        return switch (sev == null ? "" : sev.toUpperCase()) {
            case "CRITICAL"    -> 5;
            case "HIGH"        -> 4;
            case "MEDIUM"      -> 3;
            case "LOW"         -> 2;
            case "INFORMATION",
                 "INFO"        -> 1;
            case "NOISE"       -> 0;
            default            -> -1;
        };
    }

    private static JLabel makeSevBadge(String sev, int count) {
        JLabel lbl;
        Color bg, fg;
        switch (sev) {
            case "CRITICAL"               -> { bg = new Color(255, 195, 215); fg = new Color(150,   0,  80); lbl = new JLabel("Critical: " + count); }
            case "HIGH"                   -> { bg = new Color(255, 215, 215); fg = new Color(180,   0,   0); lbl = new JLabel("High: "     + count); }
            case "MEDIUM"                 -> { bg = new Color(255, 235, 200); fg = new Color(160,  80,   0); lbl = new JLabel("Medium: "   + count); }
            case "LOW"                    -> { bg = new Color(255, 252, 200); fg = new Color(140, 120,   0); lbl = new JLabel("Low: "      + count); }
            default                       -> { bg = new Color(220, 235, 255); fg = new Color( 40, 105, 195); lbl = new JLabel("Info: "     + count); }
        }
        lbl.setFont(SecretSifterApp.UI_BOLD_11);
        lbl.setOpaque(true);
        lbl.setBackground(bg);
        lbl.setForeground(fg);
        lbl.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(fg, 1, true),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
        return lbl;
    }

    private String severitySummary() {
        int c = 0, h = 0, m = 0, l = 0, i = 0;
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            Object sev = tableModel.getValueAt(r, COL_SEV);
            if (sev == null) continue;
            switch (sev.toString().toUpperCase()) {
                case "CRITICAL"            -> c++;
                case "HIGH"                -> h++;
                case "MEDIUM"              -> m++;
                case "LOW"                 -> l++;
                case "INFORMATION", "INFO" -> i++;
            }
        }
        return String.format("  ·  C:%d  H:%d  M:%d  L:%d  I:%d", c, h, m, l, i);
    }

    // =========================================================================
    // UI helpers
    // =========================================================================

    private List<String> parseUrls() {
        List<String> urls = new ArrayList<>();
        for (String line : urlArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) urls.add(trimmed);
        }
        return urls;
    }

    private static String normaliseUrl(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String s = raw.trim();
        if (s.toLowerCase().startsWith("view-source:"))
            s = s.substring("view-source:".length()).trim();
        if (!s.startsWith("http://") && !s.startsWith("https://"))
            s = "https://" + s;
        return s;
    }

    private void importUrlFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import URL list");
        fc.setFileFilter(new FileNameExtensionFilter("Text files (*.txt, *.csv)", "txt", "csv"));
        if (fc.showOpenDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        try (BufferedReader br = new BufferedReader(
                new FileReader(fc.getSelectedFile(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder(urlArea.getText().trim());
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (!t.isEmpty()) {
                    if (!sb.isEmpty()) sb.append('\n');
                    sb.append(t);
                }
            }
            urlArea.setText(sb.toString());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Could not read file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toggleColumn(int modelIndex, boolean visible) {
        javax.swing.table.TableColumnModel cm = resultsTable.getColumnModel();
        if (!visible) {
            // Remove and cache the column
            javax.swing.table.TableColumn tc = allColumns[modelIndex];
            hiddenColumns.put(modelIndex, tc);
            cm.removeColumn(tc);
        } else {
            javax.swing.table.TableColumn tc = hiddenColumns.remove(modelIndex);
            if (tc == null) return;
            cm.addColumn(tc);
            // Move to correct position: count how many columns with original index < modelIndex are visible
            int targetPos = 0;
            for (int i = 0; i < modelIndex; i++) {
                if (!hiddenColumns.containsKey(i)) targetPos++;
            }
            int currentPos = cm.getColumnCount() - 1; // just added at end
            if (currentPos != targetPos) cm.moveColumn(currentPos, targetPos);
        }
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        tableFindings.clear();
        seenUrls.clear();
        seenValueLines.clear();
        targetStatusModel.setRowCount(0);
        statusScanned.set(0);
        statusFailed.set(0);
        statusAuth.set(0);
        progressBar.setValue(0);
        progressBar.setString("");
        timerLabel.setText("");
        currentFileLabel.setText("");
        statusLabel.setText("Results cleared.");
        statusLabel.setForeground(Color.GRAY);
        // Also clear the Target URLs input and any captured request/response data so
        // a fresh scan starts from a clean slate.
        if (urlArea != null) urlArea.setText("");
        captureStore.clear();
        updateDetailsPanel(null);
        updateSummaryBar();
        updateCountBadges();
    }

    private void copyTableCell(int col) {
        int row = resultsTable.getSelectedRow();
        if (row < 0) return;
        Object val = tableModel.getValueAt(row, col);
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(val != null ? val.toString() : ""), null);
    }

    private void copyTableRow() {
        int row = resultsTable.getSelectedRow();
        if (row < 0) return;
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < tableModel.getColumnCount() - 1; c++) { // skip delete col
            if (c > 0) sb.append('\t');
            Object val = tableModel.getValueAt(row, c);
            sb.append(val != null ? val : "");
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(sb.toString()), null);
    }

    private void openUrlInBrowser() {
        int row = resultsTable.getSelectedRow();
        if (row < 0) return;
        Object val = tableModel.getValueAt(row, COL_URL);
        if (val == null) return;
        try {
            Desktop.getDesktop().browse(URI.create(val.toString()));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Cannot open browser: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // =========================================================================
    // Export
    // =========================================================================

    private List<SecretFinding> collectForExport() {
        List<SecretFinding> result = new ArrayList<>();
        synchronized (tableFindings) {
            int rows = Math.min(tableModel.getRowCount(), tableFindings.size());
            for (int r = 0; r < rows; r++) {
                SecretFinding f   = tableFindings.get(r);
                String sev  = String.valueOf(tableModel.getValueAt(r, COL_SEV));
                String conf = String.valueOf(tableModel.getValueAt(r, COL_CONF));
                // NOISE-marked findings are excluded from all exports so HTML / CSV /
                // JSON reports never include false positives the user has triaged out.
                if (isNoise(sev, conf)) continue;
                result.add(f.withSeverity(sev).withConfidence(conf));
            }
        }
        return result;
    }

    /** NOISE-marked rows captured separately so they can be exported as a "suppressed"
     *  bundle alongside the active report — useful for review and triage audit trails. */
    private List<SecretFinding> collectSuppressed() {
        List<SecretFinding> result = new ArrayList<>();
        synchronized (tableFindings) {
            int rows = Math.min(tableModel.getRowCount(), tableFindings.size());
            for (int r = 0; r < rows; r++) {
                SecretFinding f   = tableFindings.get(r);
                String sev  = String.valueOf(tableModel.getValueAt(r, COL_SEV));
                String conf = String.valueOf(tableModel.getValueAt(r, COL_CONF));
                if (!isNoise(sev, conf)) continue;
                result.add(f.withSeverity(sev).withConfidence(conf));
            }
        }
        return result;
    }

    /** Produce CSV bytes for a finding list, with column order matching the HTML report
     *  (Severity, Confidence, Rule ID, Rule Name, Key, Value, URL, Target, Line, Context). */
    private static byte[] buildCsvBytes(List<SecretFinding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("Severity,Confidence,Rule ID,Rule Name,Key,Value,URL,Target,Line,Context\n");
        for (SecretFinding f : findings) {
            sb.append('"').append(f.severity() == null ? "" : f.severity()).append("\",")
              .append('"').append(f.confidence() == null ? "" : f.confidence()).append("\",")
              .append('"').append(csvEsc(f.ruleId())).append("\",")
              .append('"').append(csvEsc(f.ruleName())).append("\",")
              .append('"').append(csvEsc(f.keyName())).append("\",")
              .append('"').append(csvEsc(f.matchedValue())).append("\",")
              .append('"').append(csvEsc(f.sourceUrl())).append("\",")
              .append('"').append(csvEsc(f.targetUrl() != null ? f.targetUrl() : "")).append("\",")
              .append(f.lineNumber()).append(',')
              .append('"').append(csvEsc(f.context() != null ? f.context().replace("\n", " ") : "")).append("\"\n");
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Produce JSON bytes for a finding list (pretty-printed). */
    private static byte[] buildJsonBytes(List<SecretFinding> findings) {
        org.json.JSONArray arr = new org.json.JSONArray();
        for (SecretFinding f : findings) {
            org.json.JSONObject obj = new org.json.JSONObject();
            obj.put("severity",     f.severity());
            obj.put("confidence",   f.confidence());
            obj.put("ruleId",       f.ruleId());
            obj.put("ruleName",     f.ruleName());
            obj.put("key",          f.keyName());
            obj.put("value",        f.matchedValue());
            obj.put("url",          f.sourceUrl());
            obj.put("target",       f.targetUrl() != null ? f.targetUrl() : "");
            obj.put("lineNumber",   f.lineNumber());
            obj.put("context",      f.context() != null ? f.context() : "");
            arr.put(obj);
        }
        return arr.toString(2).getBytes(StandardCharsets.UTF_8);
    }

    /** Date+time stamp used in every exported filename so successive exports never collide. */
    private static String exportTimestamp() {
        return java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
    }

    private void exportCsv() {
        if (tableFindings.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String ts = exportTimestamp();
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export findings as CSV");
        fc.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        fc.setSelectedFile(new File("secretsifter_findings_" + ts + ".csv"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".csv");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
            fos.write(buildCsvBytes(collectForExport()));
            statusLabel.setText("CSV saved: " + out.getName());
            statusLabel.setForeground(new Color(50, 200, 100));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save CSV: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportSuppressedCsv() {
        List<SecretFinding> suppressed = collectSuppressed();
        if (suppressed.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel,
                    "No suppressed findings to export.\n\nMark rows as NOISE (severity or confidence)\n" +
                    "during triage and they'll appear here.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String ts = exportTimestamp();
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export suppressed (NOISE) findings as CSV");
        fc.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        fc.setSelectedFile(new File("secretsifter_suppressed_" + ts + ".csv"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".csv");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
            fos.write(buildCsvBytes(suppressed));
            statusLabel.setText("Suppressed CSV saved: " + out.getName());
            statusLabel.setForeground(new Color(50, 200, 100));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save suppressed CSV: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportJson() {
        if (tableFindings.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String ts = exportTimestamp();
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export findings as JSON");
        fc.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        fc.setSelectedFile(new File("secretsifter_findings_" + ts + ".json"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".json");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
            fos.write(buildJsonBytes(collectForExport()));
            statusLabel.setText("JSON saved: " + out.getName());
            statusLabel.setForeground(new Color(50, 200, 100));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save JSON: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportHtml() {
        List<SecretFinding> snapshot   = collectForExport();
        List<SecretFinding> suppressed = collectSuppressed();
        if (snapshot.isEmpty() && suppressed.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String ts = exportTimestamp();
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save All-in-One Report Bundle (HTML + CSV + JSON)");
        fc.setFileFilter(new FileNameExtensionFilter("ZIP files (*.zip)", "zip"));
        fc.setSelectedFile(new File("secretsifter_report_" + ts + ".zip"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".zip");

        List<String> parsedUrls = parseUrls();
        String target = parsedUrls.isEmpty() ? "bulk scan" : parsedUrls.get(0);
        String mode   = settings.getTier().name();

        // All-in-one bundle: one HTML report + matching CSV / JSON / suppressed-CSV.
        // Files are date+time-stamped so successive exports never collide on disk and
        // analysts can correlate which CSV row originated from which scan run.
        try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(
                new java.io.BufferedOutputStream(new java.io.FileOutputStream(out)))) {
            byte[] html = HtmlReportGenerator.generate(snapshot, target, mode).getBytes(StandardCharsets.UTF_8);
            writeZipEntry(zos, "secretsifter_report_" + ts + ".html",     html);
            writeZipEntry(zos, "secretsifter_findings_" + ts + ".csv",    buildCsvBytes(snapshot));
            writeZipEntry(zos, "secretsifter_findings_" + ts + ".json",   buildJsonBytes(snapshot));
            if (!suppressed.isEmpty()) {
                writeZipEntry(zos, "secretsifter_suppressed_" + ts + ".csv",
                        buildCsvBytes(suppressed));
            }
            statusLabel.setText("Report bundle saved: " + out.getName());
            statusLabel.setForeground(new Color(50, 200, 100));
            int open = JOptionPane.showConfirmDialog(rootPanel,
                    "Report bundle saved to:\n" + out.getAbsolutePath() + "\n\n" +
                    "Bundle contains: HTML report, findings CSV, findings JSON" +
                    (suppressed.isEmpty() ? "." : ", and suppressed CSV.") + "\n\nOpen containing folder?",
                    "Report Saved", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
            if (open == JOptionPane.YES_OPTION) {
                try { Desktop.getDesktop().open(out.getParentFile()); } catch (Exception ignored) {}
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save report bundle: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static void writeZipEntry(java.util.zip.ZipOutputStream zos,
                                       String name, byte[] bytes) throws java.io.IOException {
        zos.putNextEntry(new java.util.zip.ZipEntry(name));
        zos.write(bytes);
        zos.closeEntry();
    }

    private void exportHtmlPerDomain() {
        List<SecretFinding> snapshot   = collectForExport();
        List<SecretFinding> suppressed = collectSuppressed();
        if (snapshot.isEmpty() && suppressed.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String ts = exportTimestamp();
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save Per-Domain Report Bundle (per-domain HTML + CSV + JSON)");
        fc.setFileFilter(new FileNameExtensionFilter("ZIP files (*.zip)", "zip"));
        fc.setSelectedFile(new File("secretsifter_reports_" + ts + ".zip"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".zip");
        String mode = settings.getTier().name();
        Map<String, String> domainReports = HtmlReportGenerator.generatePerDomain(snapshot, mode);

        // Per-domain ZIP: one HTML per domain + a single combined CSV / JSON for the
        // whole scan + suppressed CSV.  All filenames carry the same timestamp so the
        // bundle is self-consistent and successive exports never collide on disk.
        try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(
                new java.io.BufferedOutputStream(new java.io.FileOutputStream(out)))) {
            for (Map.Entry<String, String> entry : domainReports.entrySet()) {
                String safeName  = entry.getKey().replaceAll("[^a-zA-Z0-9._-]", "_");
                String entryName = safeName + "_secretsifter_" + ts + ".html";
                writeZipEntry(zos, entryName, entry.getValue().getBytes(StandardCharsets.UTF_8));
            }
            writeZipEntry(zos, "secretsifter_findings_" + ts + ".csv",  buildCsvBytes(snapshot));
            writeZipEntry(zos, "secretsifter_findings_" + ts + ".json", buildJsonBytes(snapshot));
            if (!suppressed.isEmpty()) {
                writeZipEntry(zos, "secretsifter_suppressed_" + ts + ".csv",
                        buildCsvBytes(suppressed));
            }
            statusLabel.setText("ZIP saved: " + out.getName()
                    + "  (" + domainReports.size() + " domain report"
                    + (domainReports.size() == 1 ? "" : "s") + " + CSV/JSON)");
            statusLabel.setForeground(new Color(0, 130, 0));
            int open = JOptionPane.showConfirmDialog(rootPanel,
                    "Per-domain ZIP saved to:\n" + out.getAbsolutePath() + "\n\n"
                    + domainReports.size() + " domain HTML report"
                    + (domainReports.size() == 1 ? "" : "s")
                    + " + combined CSV + combined JSON"
                    + (suppressed.isEmpty() ? "." : " + suppressed CSV.")
                    + "\n\nOpen containing folder?",
                    "Reports Saved", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
            if (open == JOptionPane.YES_OPTION) {
                try { Desktop.getDesktop().open(out.getParentFile()); } catch (Exception ignored) {}
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save ZIP: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importAndScanHar() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import HAR file");
        fc.setFileFilter(new FileNameExtensionFilter("HAR files (*.har)", "har"));
        if (fc.showOpenDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File harFile = fc.getSelectedFile();
        if (harFile == null) return;

        statusLabel.setText("Reading " + harFile.getName() + "…");
        statusLabel.setForeground(new Color(0, 100, 200));
        progressBar.setIndeterminate(true);

        new Thread(() -> {
            try {
                String raw;
                try (InputStream is = new FileInputStream(harFile)) {
                    raw = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                }
                org.json.JSONObject har     = new org.json.JSONObject(raw);
                org.json.JSONArray  entries = har.getJSONObject("log").getJSONArray("entries");
                int total = entries.length(), scanned = 0;

                for (int i = 0; i < total; i++) {
                    org.json.JSONObject entry    = entries.getJSONObject(i);
                    org.json.JSONObject request  = entry.getJSONObject("request");
                    org.json.JSONObject response = entry.getJSONObject("response");
                    String url    = request.optString("url", "");
                    int    status = response.optInt("status", 0);
                    if (status < 200 || status >= 300) continue;
                    if (settings.isExternalCdn(url)) continue;
                    final String fUrl = url;

                    // ── Collect request headers (also used for CaptureStore) ──
                    String method = request.optString("method", "GET");
                    StringBuilder reqHdrBlob = new StringBuilder();
                    org.json.JSONArray reqHeaders = request.optJSONArray("headers");
                    if (reqHeaders != null) {
                        for (int h = 0; h < reqHeaders.length(); h++) {
                            org.json.JSONObject hdr = reqHeaders.optJSONObject(h);
                            if (hdr == null) continue;
                            String hName = hdr.optString("name",  "");
                            String hVal  = hdr.optString("value", "");
                            if (!hName.isBlank() && !hVal.isBlank())
                                reqHdrBlob.append(hName).append(": ").append(hVal).append("\n");
                        }
                    }

                    // Request body text
                    org.json.JSONObject postData = request.optJSONObject("postData");
                    String postText = postData == null ? null : postData.optString("text", "");
                    String postMime = postData == null ? null : postData.optString("mimeType", "text/plain");
                    if (postText != null && postText.isBlank()) postText = null;

                    // Response headers
                    StringBuilder respHdrBlob = new StringBuilder();
                    org.json.JSONArray respHeaders = response.optJSONArray("headers");
                    if (respHeaders != null) {
                        for (int h = 0; h < respHeaders.length(); h++) {
                            org.json.JSONObject hdr = respHeaders.optJSONObject(h);
                            if (hdr == null) continue;
                            String hName = hdr.optString("name",  "");
                            String hVal  = hdr.optString("value", "");
                            if (!hName.isBlank() && !hVal.isBlank())
                                respHdrBlob.append(hName).append(": ").append(hVal).append("\n");
                        }
                    }
                    String statusText = response.optString("statusText", "");

                    // Response body
                    org.json.JSONObject content = response.optJSONObject("content");
                    String respMime = content == null ? "" : content.optString("mimeType", "");
                    String respBody = content == null ? "" : content.optString("text", "");
                    String respEnc  = content == null ? "" : content.optString("encoding", "");
                    if ("base64".equalsIgnoreCase(respEnc)) respBody = "";

                    // ── Store complete capture for the Details side-panel.  Use merge()
                    //    so any subsequent scanAndAppend on this URL can't clobber it.
                    captureStore.merge(
                            url,
                            reqHdrBlob.toString(), postText,
                            respBody, respMime,
                            status, "HTTP/1.1 " + status + " " + statusText,
                            respHdrBlob.toString(), method);

                    // ── Scan request headers (Authorization, Bearer/JWT, etc.) ──
                    if (reqHdrBlob.length() > 0) {
                        final String blob = reqHdrBlob.toString();
                        SwingUtilities.invokeLater(() -> scanAndAppend(blob, "text/plain", fUrl + " [REQ-HEADERS]", fUrl));
                    }
                    // ── Scan request body ──
                    if (postText != null) {
                        final String fPost = postText, fMime2 = postMime;
                        SwingUtilities.invokeLater(() -> scanAndAppend(fPost, fMime2, fUrl + " [REQ-BODY]", fUrl));
                    }
                    // ── Scan response body ──
                    if (!respBody.isBlank()) {
                        String mt = respMime.toLowerCase();
                        if (mt.contains("javascript") || mt.contains("text/html")
                                || mt.contains("application/json") || mt.contains("text/plain")
                                || mt.contains("application/xml") || mt.contains("text/xml")
                                || mt.contains("form-urlencoded")) {
                            final String fBody = respBody, fMime = respMime;
                            SwingUtilities.invokeLater(() -> {
                                currentFileLabel.setText("→ " + fUrl);
                                scanAndAppend(fBody, fMime, fUrl, fUrl);
                            });
                        }
                    }
                    scanned++;
                }
                final int fScanned = scanned, fTotal = total;
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    progressBar.setValue(0);
                    currentFileLabel.setText("");
                    statusLabel.setText("HAR scan complete — " + fScanned + " responses scanned ("
                            + fTotal + " entries in file)." + severitySummary());
                    statusLabel.setForeground(new Color(0, 140, 60));
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    statusLabel.setText("HAR import failed: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                    JOptionPane.showMessageDialog(rootPanel,
                            "Could not parse HAR file:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "SecretSifter-HarImport").start();
    }

    private static File ensureExtension(File f, String ext) {
        return f.getName().toLowerCase().endsWith(ext) ? f
                : new File(f.getAbsolutePath() + ext);
    }

    private static String csvEsc(String s) {
        if (s == null) return "";
        return s.replace("\"", "\"\"");
    }

    // =========================================================================
    // Cell renderers
    // =========================================================================

    // ── Row colour + masking renderer ─────────────────────────────────────────

    private class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focused, int row, int col) {
            // The `col` parameter is the VIEW index, which can drift from the model
            // index whenever a user hides/reorders columns.  Convert before comparing
            // against model constants — otherwise the wrong column gets masked.
            int modelCol = table.convertColumnIndexToModel(col);

            // Apply masking before rendering
            Object display = value;
            if (modelCol == COL_VAL && maskValues && value != null && !value.toString().isEmpty()) {
                display = "••••••••••••";
            } else if (maskUrls && value != null && !value.toString().isEmpty()
                       && (modelCol == COL_URL || modelCol == COL_TARGET)) {
                // Mask URL covers BOTH URL and Target columns — both contain origin URLs
                // that an analyst may want to redact when sharing screenshots.
                display = "••••••••••••";
            }

            Component c = super.getTableCellRendererComponent(
                    table, display, selected, focused, row, col);
            int modelRow = table.convertRowIndexToModel(row);
            Object sev  = tableModel.getValueAt(modelRow, COL_SEV);
            Object conf = tableModel.getValueAt(modelRow, COL_CONF);
            boolean noise = (sev  != null && "NOISE".equalsIgnoreCase(sev.toString())) ||
                            (conf != null && "NOISE".equalsIgnoreCase(conf.toString()));
            if (!selected) {
                Color bg = noise
                        ? SEV_BG.get("NOISE")
                        : (sev != null
                                ? SEV_BG.getOrDefault(sev.toString().toUpperCase(), Color.WHITE)
                                : Color.WHITE);
                c.setBackground(bg);
            }
            if (col == COL_URL || col == 8) {
                setFont(SecretSifterApp.UI_PLAIN_11);
            } else {
                setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            }
            // Grey out text for NOISE rows so the whole row reads as deprioritised.
            if (noise && !selected) {
                setForeground(new Color(120, 120, 120));
            } else {
                setForeground(selected ? Color.WHITE : Color.BLACK);
            }
            return c;
        }
    }

    // ── Severity pill/badge renderer for the Severity column ─────────────────

    private class SeverityBadgeRenderer extends JLabel implements javax.swing.table.TableCellRenderer {

        SeverityBadgeRenderer() {
            setHorizontalAlignment(CENTER);
            setOpaque(true);
        }

        private Color badgeBg  = Color.GRAY;
        private Color cellBg   = Color.WHITE;
        private boolean selRow = false;

        @Override
        public Component getTableCellRendererComponent(JTable tbl, Object val,
                boolean sel, boolean foc, int row, int col) {
            String sev = val != null ? val.toString().toUpperCase() : "";
            setText(sev);
            selRow  = sel;
            badgeBg = SEV_BADGE.getOrDefault(sev, new Color(110, 110, 110));
            cellBg  = sel ? tbl.getSelectionBackground()
                          : SEV_BG.getOrDefault(sev, tbl.getBackground());
            setBackground(cellBg);
            return this;
        }

        @Override
        protected void paintComponent(Graphics g) {
            // Fill cell background (severity row tint or selection highlight)
            g.setColor(cellBg);
            g.fillRect(0, 0, getWidth(), getHeight());
            if (getText().isEmpty()) return;

            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                    RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            Font f = SecretSifterApp.UI_BOLD_10;
            g2.setFont(f);
            FontMetrics fm = g2.getFontMetrics();
            int tw   = fm.stringWidth(getText());
            int padX = 7, padY = 2;
            int bw   = tw + padX * 2;
            int bh   = fm.getHeight() + padY * 2;
            int bx   = (getWidth()  - bw) / 2;
            int by   = (getHeight() - bh) / 2;

            if (!selRow) {
                // Draw coloured pill
                g2.setColor(badgeBg);
                g2.fillRoundRect(bx, by, bw, bh, bh, bh);
            }
            g2.setColor(Color.WHITE);
            g2.drawString(getText(), bx + padX, by + padY + fm.getAscent());
            g2.dispose();
        }
    }

    // ── Delete button renderer ────────────────────────────────────────────────

    private static class DeleteButtonRenderer extends DefaultTableCellRenderer {
        private final JButton btn;
        DeleteButtonRenderer() {
            btn = new JButton("✕");
            btn.setFont(SecretSifterApp.UI_BOLD_11);
            btn.setForeground(new Color(180, 0, 0));
            btn.setBorderPainted(false);
            btn.setContentAreaFilled(false);
            btn.setFocusPainted(false);
            btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            btn.setToolTipText("Remove this finding");
        }
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean foc, int row, int col) { return btn; }
    }
}
