package com.secretsifter;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;

/**
 * About dialog — shown when the user clicks the ⓘ button in the bottom bar.
 */
public class AboutDialog extends JDialog {

    private static final String VERSION = "1.8.3";
    private static final String AUTHOR  = "Hemanth Gorijala";
    private static final String EMAIL   = "gorijala2k16@gmail.com";

    public AboutDialog(Window owner) {
        super(owner, "About OWASP SecretSifter", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(false);
        buildUI();
        pack();
        setLocationRelativeTo(owner);
    }

    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.setBackground(new Color(30, 30, 30));

        // ── Top: icon + app name + version ───────────────────────────────────
        JPanel header = new JPanel(new BorderLayout(16, 0));
        header.setBackground(new Color(24, 24, 24));
        header.setBorder(new EmptyBorder(20, 24, 20, 24));

        // App icon — use the 64 px version directly (no scaling needed)
        java.net.URL iconUrl = AboutDialog.class.getResource("/icon_64.png");
        if (iconUrl == null) iconUrl = AboutDialog.class.getResource("/icon.png");
        if (iconUrl != null) {
            ImageIcon raw = new ImageIcon(iconUrl);
            Image scaled = raw.getImage().getScaledInstance(64, 64, Image.SCALE_SMOOTH);
            JLabel iconLbl = new JLabel(new ImageIcon(scaled));
            header.add(iconLbl, BorderLayout.WEST);
        }

        // Name + version block
        JPanel nameBlock = new JPanel();
        nameBlock.setLayout(new BoxLayout(nameBlock, BoxLayout.Y_AXIS));
        nameBlock.setOpaque(false);

        JLabel nameLbl = new JLabel("OWASP SecretSifter");
        nameLbl.setFont(new Font(".AppleSystemUIFont", Font.BOLD, 22));
        nameLbl.setForeground(Color.WHITE);

        JLabel taglineLbl = new JLabel("Live Credentials & Secrets Scanner");
        taglineLbl.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 13));
        taglineLbl.setForeground(new Color(160, 160, 160));

        JLabel versionLbl = new JLabel("Version " + VERSION);
        versionLbl.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 12));
        versionLbl.setForeground(new Color(120, 120, 120));

        nameBlock.add(nameLbl);
        nameBlock.add(Box.createVerticalStrut(4));
        nameBlock.add(taglineLbl);
        nameBlock.add(Box.createVerticalStrut(2));
        nameBlock.add(versionLbl);

        header.add(nameBlock, BorderLayout.CENTER);
        root.add(header, BorderLayout.NORTH);

        // ── Body: info rows ───────────────────────────────────────────────────
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setBackground(new Color(30, 30, 30));
        body.setBorder(new EmptyBorder(4, 0, 4, 0));

        // Developed by row — name is displayed as a mailto hyperlink
        body.add(makeRow("Developed by", AUTHOR, EMAIL));
        body.add(makeLinkRow("Project", "owasp.org/www-project-secretsifter",
                "https://owasp.org/www-project-secretsifter/"));
        body.add(makeSeparator());

        // What it does
        body.add(makeSectionHeader("About"));
        body.add(makeTextRow(
                "OWASP SecretSifter scans web responses, JavaScript files, and HAR archives\n" +
                "for leaked credentials, API keys, tokens, and other sensitive secrets.\n" +
                "It ships 437 built-in detection rules across AWS, GitHub, Stripe, Twilio,\n" +
                "Google, and 200+ more services, with optional live key validation."));
        body.add(makeSeparator());

        // How to use
        body.add(makeSectionHeader("How to Use"));
        body.add(makeTextRow(
                "1. Paste one or more URLs in the Scan tab (one per line).\n" +
                "2. Adjust concurrency and depth in Settings if needed.\n" +
                "3. Click  Start Scan  — findings appear in the results table in real time.\n" +
                "4. Click a row to inspect the matched value and surrounding context.\n" +
                "5. Export findings as CSV, HTML report, or per-domain ZIP."));
        body.add(makeSeparator());

        // HAR / Browser mode
        body.add(makeSectionHeader("HAR & Browser Mode"));
        body.add(makeTextRow(
                "Use  Import HAR  to scan a saved browser session (Burp / DevTools).\n" +
                "Enable  Browser Mode  in Settings to crawl dynamically-loaded JS with\n" +
                "a headless browser. Uses Microsoft Edge automatically on Windows 10/11\n" +
                "(no setup required). Falls back to Playwright Chromium if Edge is not found."));
        body.add(makeSeparator());

        // REST API
        body.add(makeSectionHeader("REST API — Automated Scripting"));
        body.add(makeTextRow(
                "A full REST API is available when the MCP server is enabled (Settings → AI / MCP).\n" +
                "All endpoints require  Authorization: Bearer <token>  header.\n\n" +
                "POST   /api/scan              Start a scan\n" +
                "GET    /api/scan/status       Poll scan progress\n" +
                "DELETE /api/scan              Cancel running scan\n" +
                "GET    /api/findings          Get all findings\n" +
                "DELETE /api/findings          Clear all findings\n" +
                "PATCH  /api/findings/{n}      Update finding severity\n" +
                "DELETE /api/findings/{n}      Delete one finding\n" +
                "POST   /api/report            Export CSV / JSON / HTML report\n" +
                "GET    /api/settings          Read scanner settings\n" +
                "PATCH  /api/settings          Update scanner settings\n" +
                "GET    /api/targets           Per-target scan outcomes\n" +
                "GET    /api/rules             Get custom rules\n" +
                "PUT    /api/rules             Replace all custom rules\n" +
                "POST   /api/rules             Add one custom rule\n" +
                "GET    /api/logs              Read log buffer\n" +
                "DELETE /api/logs              Clear log buffer\n\n" +
                "See  Settings → AI / MCP → Download Setup Guide  for Python / curl examples."));
        body.add(makeSeparator());

        // MCP / AI integration
        body.add(makeSectionHeader("MCP & AI Integration"));
        body.add(makeTextRow(
                "SecretSifter Desktop registers as  secretsifter-desktop  in Claude's MCP config.\n" +
                "This avoids conflicts with the Burp extension (which uses  secretsifter ).\n" +
                "Both can coexist in the same claude_desktop_config.json.\n\n" +
                "Transport: HTTP (JSON-RPC 2.0)   Protocol: MCP 2025-06-18\n" +
                "Endpoint:  POST http://localhost:<port>/mcp\n\n" +
                "Quick setup — Claude Code CLI:\n" +
                "  claude mcp add --transport http secretsifter-desktop \\\n" +
                "    http://localhost:<port>/mcp \\\n" +
                "    --header \"Authorization: Bearer <token>\"\n\n" +
                "Quick setup — Claude Desktop:\n" +
                "  Paste the JSON snippet from  Settings → AI / MCP → Copy JSON\n" +
                "  into  %APPDATA%\\Claude\\claude_desktop_config.json  and restart.\n\n" +
                "27 MCP tools available — start scans, read findings, export reports,\n" +
                "manage custom rules and settings, scan HAR files, and more.\n" +
                "See  Settings → AI / MCP → Download Setup Guide  for full reference."));

        JScrollPane bodyScroll = new JScrollPane(body,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        bodyScroll.setBorder(null);
        bodyScroll.getViewport().setBackground(new Color(30, 30, 30));
        root.add(bodyScroll, BorderLayout.CENTER);

        // ── Footer: copyright + close button ─────────────────────────────────
        JPanel footer = new JPanel(new BorderLayout(0, 0));
        footer.setBackground(new Color(24, 24, 24));
        footer.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(55, 55, 55)));

        JLabel copyrightLbl = new JLabel("\u00A9 2026 OWASP SecretSifter · MIT License");
        copyrightLbl.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 11));
        copyrightLbl.setForeground(new Color(100, 100, 100));
        copyrightLbl.setBorder(new EmptyBorder(0, 16, 0, 0));
        footer.add(copyrightLbl, BorderLayout.WEST);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 16, 10));
        btnPanel.setOpaque(false);

        JButton closeBtn = new JButton("Close");
        closeBtn.setFont(new Font(".AppleSystemUIFont", Font.BOLD, 12));
        closeBtn.setBackground(new Color(0, 100, 200));
        closeBtn.setForeground(Color.WHITE);
        closeBtn.setFocusPainted(false);
        closeBtn.setBorderPainted(false);
        closeBtn.setOpaque(true);
        closeBtn.setPreferredSize(new Dimension(88, 30));
        closeBtn.addActionListener(e -> dispose());
        btnPanel.add(closeBtn);
        footer.add(btnPanel, BorderLayout.EAST);

        root.add(footer, BorderLayout.SOUTH);

        setContentPane(root);
        setPreferredSize(new Dimension(560, 700));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** One key-value info row (email value becomes a clickable hyperlink). */
    private static JPanel makeRow(String key, String value, String mailtoAddress) {
        JPanel row = new JPanel(new BorderLayout(12, 0));
        row.setOpaque(false);
        row.setBorder(new EmptyBorder(10, 24, 10, 24));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));

        JLabel keyLbl = new JLabel(key);
        keyLbl.setFont(new Font(".AppleSystemUIFont", Font.BOLD, 12));
        keyLbl.setForeground(new Color(200, 200, 200));
        keyLbl.setPreferredSize(new Dimension(105, 20));

        JLabel valLbl;
        if (mailtoAddress != null) {
            valLbl = new JLabel("<html><a href=''>" + value + "</a></html>");
            valLbl.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 12));
            valLbl.setForeground(new Color(80, 150, 255));
            valLbl.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            valLbl.addMouseListener(new MouseAdapter() {
                @Override public void mouseClicked(MouseEvent e) {
                    try {
                        Desktop.getDesktop().mail(new URI("mailto:" + mailtoAddress));
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(null,
                                "Could not open mail client.\nEmail: " + mailtoAddress,
                                "Contact", JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            });
        } else {
            valLbl = new JLabel(value);
            valLbl.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 12));
            valLbl.setForeground(new Color(220, 220, 220));
        }

        row.add(keyLbl, BorderLayout.WEST);
        row.add(valLbl, BorderLayout.CENTER);
        return row;
    }

    /** One key-value row whose value opens a web URL in the default browser. */
    private static JPanel makeLinkRow(String key, String display, String url) {
        JPanel row = new JPanel(new BorderLayout(12, 0));
        row.setOpaque(false);
        row.setBorder(new EmptyBorder(10, 24, 10, 24));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));

        JLabel keyLbl = new JLabel(key);
        keyLbl.setFont(new Font(".AppleSystemUIFont", Font.BOLD, 12));
        keyLbl.setForeground(new Color(200, 200, 200));
        keyLbl.setPreferredSize(new Dimension(105, 20));

        JLabel valLbl = new JLabel("<html><a href=''>" + display + "</a></html>");
        valLbl.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 12));
        valLbl.setForeground(new Color(80, 150, 255));
        valLbl.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        valLbl.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                try { Desktop.getDesktop().browse(new URI(url)); }
                catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, url, "Project", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        row.add(keyLbl, BorderLayout.WEST);
        row.add(valLbl, BorderLayout.CENTER);
        return row;
    }

    private static JPanel makeSectionHeader(String title) {
        JLabel lbl = new JLabel(title);
        lbl.setFont(new Font(".AppleSystemUIFont", Font.BOLD, 13));
        lbl.setForeground(new Color(210, 210, 210));
        lbl.setHorizontalAlignment(SwingConstants.LEFT);

        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);
        p.setBorder(new EmptyBorder(14, 24, 4, 24));
        p.add(lbl, BorderLayout.WEST);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        return p;
    }

    private static JPanel makeTextRow(String text) {
        JTextArea ta = new JTextArea(text);
        ta.setEditable(false);
        ta.setFocusable(false);
        ta.setOpaque(false);
        ta.setFont(new Font(".AppleSystemUIFont", Font.PLAIN, 12));
        ta.setForeground(new Color(200, 200, 200));
        ta.setLineWrap(true);
        ta.setWrapStyleWord(true);
        ta.setBorder(new EmptyBorder(0, 24, 10, 24));

        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);
        p.add(ta, BorderLayout.CENTER);
        return p;
    }

    private static JSeparator makeSeparator() {
        JSeparator sep = new JSeparator();
        sep.setForeground(new Color(50, 50, 50));
        sep.setBackground(new Color(30, 30, 30));
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        return sep;
    }
}
