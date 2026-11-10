package com.secretsifter;

import com.formdev.flatlaf.FlatDarkLaf;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.UUID;

/**
 * SecretSifter — Standalone Secret Scanner
 *
 * Double-click or run:  java -jar secretsifter.jar
 *
 * Browser Mode uses Microsoft Edge (auto-detected on Windows 10/11) or Playwright's bundled
 * Chromium (downloaded automatically on first launch, ~120 MB, if Edge is not found).
 */
public class SecretSifterApp {

    // San Francisco (macOS system font) — bypasses FlatLaf's Inter completely.
    // Direct construction avoids deriveFont() losing the physical font mapping.
    public static final Font UI_PLAIN_10 = new Font(".AppleSystemUIFont", Font.PLAIN, 10);
    public static final Font UI_PLAIN_11 = new Font(".AppleSystemUIFont", Font.PLAIN, 11);
    public static final Font UI_PLAIN_12 = new Font(".AppleSystemUIFont", Font.PLAIN, 12);
    public static final Font UI_PLAIN_13 = new Font(".AppleSystemUIFont", Font.PLAIN, 13);
    public static final Font UI_BOLD_10  = new Font(".AppleSystemUIFont", Font.BOLD,  10);
    public static final Font UI_BOLD_11  = new Font(".AppleSystemUIFont", Font.BOLD,  11);
    public static final Font UI_BOLD_12  = new Font(".AppleSystemUIFont", Font.BOLD,  12);
    public static final Font UI_BOLD_13  = new Font(".AppleSystemUIFont", Font.BOLD,  13);
    /** @deprecated use UI_BOLD_11 / UI_PLAIN_11 etc. directly */
    public static final Font UI_FONT = UI_PLAIN_13;

    public static void main(String[] args) {
        // Apply FlatLaf dark theme before any Swing component is created
        // Disable Inter font to avoid glyph rendering issues in bundled JRE
        System.setProperty("flatlaf.useInterFont", "false");
        // Set defaultFont before setup so FlatLaf picks it up
        UIManager.put("defaultFont", UI_PLAIN_13);
        try {
            FlatDarkLaf.setup();
        } catch (Exception ignored) {
            try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); }
            catch (Exception ignored2) {}
        }
        // Override FlatLaf's LAF-layer fonts so Inter doesn't bleed through
        javax.swing.UIDefaults lafDefaults = UIManager.getLookAndFeelDefaults();
        for (java.util.Enumeration<Object> keys = lafDefaults.keys(); keys.hasMoreElements();) {
            Object key = keys.nextElement();
            Object val = lafDefaults.get(key);
            if (val instanceof Font) {
                Font f2 = (Font) val;
                int style = f2.isBold() ? Font.BOLD : Font.PLAIN;
                int size  = Math.round(f2.getSize2D());
                lafDefaults.put(key, new Font(".AppleSystemUIFont", style, size));
            }
        }
        for (String key : new String[]{"Label.font", "CheckBox.font", "TitledBorder.font"}) {
            lafDefaults.put(key, UI_BOLD_13);
        }

        // Launch the main window immediately; install Chromium in the background if needed
        SwingUtilities.invokeLater(SecretSifterApp::launch);
    }

    // =========================================================================
    // Main application window
    // =========================================================================

    private static void launch() {
        // ── Logger — routes to stdout/stderr AND to the Logs tab ──────────────
        LogManager logManager = new LogManager();

        // ── Settings + persistence ────────────────────────────────────────────
        AppPrefs     prefs    = new AppPrefs();
        ScanSettings settings = new ScanSettings();
        settings.loadFromPrefs(prefs);

        // ── Core engine ───────────────────────────────────────────────────────
        SecretScanner scanner = new SecretScanner(settings, logManager);
        HttpFetcher   fetcher = new HttpFetcher(logManager);

        // ── Panels ────────────────────────────────────────────────────────────
        BulkScanPanel  bulkPanel     = new BulkScanPanel(scanner, settings, fetcher, logManager);

        // ── MCP server — token and port from prefs, generated once on first run ──
        String mcpToken = prefs.getString("mcp.token");
        if (mcpToken == null || mcpToken.isBlank()) {
            mcpToken = UUID.randomUUID().toString().replace("-", "");
            prefs.setString("mcp.token", mcpToken);
        }
        int mcpPort = 7483;
        String mcpPortStr = prefs.getString("mcp.port");
        if (mcpPortStr != null) {
            try { mcpPort = Integer.parseInt(mcpPortStr); } catch (NumberFormatException ignored) {}
        }
        McpServer mcpServer = new McpServer(mcpPort, mcpToken, bulkPanel, settings, logManager, prefs);
        bulkPanel.setMcpServer(mcpServer);   // enables the keyless "Claude via MCP" triage path
        if (Boolean.TRUE.equals(prefs.getBoolean("mcp.enabled"))) {
            try { mcpServer.start(); } catch (Exception e) { logManager.logToError("MCP server failed to start: " + e.getMessage()); }
        }

        ProxyPanel     proxyPanel    = new ProxyPanel(scanner, logManager, bulkPanel::addFindings);
        proxyPanel.setCaptureStore(bulkPanel.getCaptureStore());
        SettingsPanel  settingsPanel = new SettingsPanel(settings, prefs, mcpServer, proxyPanel.getPanel());
        LogPanel       logPanel      = new LogPanel(logManager);

        // ── Main window ───────────────────────────────────────────────────────
        JFrame frame = new JFrame("OWASP SecretSifter — AI-Powered Secrets Scanner");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1420, 820);
        frame.setMinimumSize(new Dimension(900, 600));

        // Center on screen
        Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
        frame.setLocation(
                Math.max(0, (screen.width  - 1420) / 2),
                Math.max(0, (screen.height -  820) / 2));

        // Set taskbar/window icon — provide all sizes so Windows picks the right one
        // (16 px for title bar, 32/48 px for taskbar, 256 px for thumbnails).
        try {
            int[] sizes = {16, 24, 32, 48, 64, 128, 256};
            java.util.List<java.awt.Image> icons = new java.util.ArrayList<>();
            for (int sz : sizes) {
                java.net.URL u = SecretSifterApp.class.getResource("/icon_" + sz + ".png");
                if (u != null) icons.add(new ImageIcon(u).getImage());
            }
            if (!icons.isEmpty()) frame.setIconImages(icons);
        } catch (Exception ignored) {}

        // ── Tab layout ────────────────────────────────────────────────────────
        // Each page carries a faint OWASP owl watermark on its background (Branding.watermark).
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Scan",     Branding.watermark(bulkPanel.getPanel()));
        tabs.addTab("Settings", Branding.watermark(settingsPanel.getPanel()));
        tabs.addTab("Logs",     Branding.watermark(logPanel.getPanel()));

        frame.setContentPane(tabs);

        // ⓘ About button — glass pane overlay pinned to the top-right corner
        JPanel glass = new JPanel(null);
        glass.setOpaque(false);

        JLabel aboutTabBtn = new JLabel("\u24D8");  // ⓘ
        aboutTabBtn.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 16));
        aboutTabBtn.setForeground(new Color(100, 150, 220));
        aboutTabBtn.setToolTipText("About SecretSifter");
        aboutTabBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        aboutTabBtn.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                new com.secretsifter.AboutDialog(frame).setVisible(true);
            }
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                aboutTabBtn.setForeground(new Color(150, 190, 255));
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) {
                aboutTabBtn.setForeground(new Color(100, 150, 220));
            }
        });

        // "AI-Powered" pill — visible on all tabs, sits left of the ⓘ button.
        // The lightning bolt is painted as a vector (the ⚡ emoji glyph isn't in
        // the macOS UI font, so it was being silently dropped).
        JLabel aiLabel = new JLabel("AI-Powered") {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                // pill background
                g2.setColor(new Color(30, 60, 110, 200));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                g2.setColor(new Color(60, 120, 210, 160));
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
                // lightning bolt, vector-drawn so it always renders
                double bx = 9, bh = getHeight() * 0.62, bw = bh * 0.52;
                double by = (getHeight() - bh) / 2.0;
                double[][] pts = {
                    {0.62, 0.00}, {0.10, 0.55}, {0.42, 0.55},
                    {0.30, 1.00}, {0.92, 0.42}, {0.52, 0.42}
                };
                java.awt.geom.Path2D bolt = new java.awt.geom.Path2D.Double();
                for (int i = 0; i < pts.length; i++) {
                    double px = bx + pts[i][0] * bw, py = by + pts[i][1] * bh;
                    if (i == 0) bolt.moveTo(px, py); else bolt.lineTo(px, py);
                }
                bolt.closePath();
                g2.setColor(new Color(255, 214, 64)); // amber bolt
                g2.fill(bolt);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        aiLabel.setFont(new Font(".AppleSystemUIFont", Font.BOLD, 11));
        aiLabel.setForeground(new Color(130, 180, 255));
        aiLabel.setOpaque(false);
        aiLabel.setHorizontalAlignment(SwingConstants.CENTER);
        aiLabel.setBorder(BorderFactory.createEmptyBorder(0, 16, 0, 0)); // leave room for the bolt
        aiLabel.setToolTipText("AI-ready via MCP — connect Claude, Cursor, or any MCP client");

        glass.add(aiLabel);
        glass.add(aboutTabBtn);
        frame.setGlassPane(glass);
        glass.setVisible(true);

        // Reposition controls whenever the frame is resized
        java.awt.event.ComponentAdapter positioner = new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                int btnW = 30, btnH = 28;
                aboutTabBtn.setBounds(frame.getWidth() - btnW - 14, 6, btnW, btnH);
                int pillW = 112, pillH = 22;
                aiLabel.setBounds(frame.getWidth() - btnW - pillW - 22, 9, pillW, pillH);
            }
            @Override public void componentShown(java.awt.event.ComponentEvent e) {
                componentResized(e);
            }
        };
        frame.addComponentListener(positioner);

        // Save settings and stop MCP server when window is closed
        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent e) {
                settings.saveToPrefs(prefs);
                mcpServer.stop();
                proxyPanel.shutdown();
            }
        });

        frame.setVisible(true);
        // Trigger initial positioning after the frame is visible
        aboutTabBtn.setBounds(frame.getWidth() - 44, 6, 30, 28);
        aiLabel.setBounds(frame.getWidth() - 44 - 112 - 8, 9, 112, 22);
    }
}
