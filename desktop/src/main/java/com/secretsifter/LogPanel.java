package com.secretsifter;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * "Logs" tab — live view of all SecretSifter activity with timestamped entries.
 * Receives lines from {@link LogManager} and displays them colour-coded.
 * Provides Clear and Download buttons.
 */
public class LogPanel {

    private static final DateTimeFormatter FILE_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    // Colours for INFO / ERROR lines (work on dark background)
    private static final Color COLOR_INFO      = new Color(200, 200, 200);
    private static final Color COLOR_ERROR     = new Color(255, 100,  90);
    private static final Color COLOR_TIMESTAMP = new Color(120, 120, 120);

    private final LogManager logManager;
    private JPanel     rootPanel;
    private JTextPane  logPane;
    private StyledDocument doc;
    private JCheckBox  autoScrollBox;
    private JLabel     lineCountLabel;
    private JTextField searchField;
    private JLabel     matchCountLabel;
    private int        lineCount = 0;

    public LogPanel(LogManager logManager) {
        this.logManager = logManager;
        if (SwingUtilities.isEventDispatchThread()) buildUi();
        else try { SwingUtilities.invokeAndWait(this::buildUi); }
             catch (Exception e) { SwingUtilities.invokeLater(this::buildUi); }
    }

    public JPanel getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(6, 6));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ── Toolbar ───────────────────────────────────────────────────────────
        // Two-row header stacked with BoxLayout — always shows both rows.
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));

        // Row 1: action buttons + auto-scroll + line count
        JPanel actionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        JButton clearBtn    = new JButton("Clear Logs");
        JButton downloadBtn = new JButton("Download Logs (.txt)");
        autoScrollBox = new JCheckBox("Auto-scroll", true);
        lineCountLabel = new JLabel("0 lines");
        lineCountLabel.setForeground(Color.GRAY);
        lineCountLabel.setFont(SecretSifterApp.UI_BOLD_11);

        clearBtn.addActionListener(e -> onClear());
        downloadBtn.addActionListener(e -> onDownload());
        autoScrollBox.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) scrollToBottom();
        });

        actionsRow.add(clearBtn);
        actionsRow.add(downloadBtn);
        actionsRow.add(Box.createHorizontalStrut(16));
        actionsRow.add(autoScrollBox);
        actionsRow.add(Box.createHorizontalStrut(16));
        actionsRow.add(lineCountLabel);

        // Row 2: search bar (always fully visible)
        JPanel searchRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        JLabel searchLbl = new JLabel("Search:");
        searchLbl.setForeground(Color.GRAY);
        searchField = new JTextField(30);
        searchField.setToolTipText("Filter/highlight log lines (case-insensitive)");
        JButton clearSearchBtn = new JButton("✕");
        clearSearchBtn.setToolTipText("Clear search");
        clearSearchBtn.setMargin(new Insets(1, 5, 1, 5));
        clearSearchBtn.addActionListener(e -> { searchField.setText(""); doSearch(""); });
        matchCountLabel = new JLabel("");
        matchCountLabel.setForeground(new Color(80, 180, 255));
        matchCountLabel.setFont(SecretSifterApp.UI_BOLD_11);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { doSearch(searchField.getText()); }
            @Override public void removeUpdate(DocumentEvent e)  { doSearch(searchField.getText()); }
            @Override public void changedUpdate(DocumentEvent e) { doSearch(searchField.getText()); }
        });

        searchRow.add(searchLbl);
        searchRow.add(searchField);
        searchRow.add(clearSearchBtn);
        searchRow.add(matchCountLabel);

        headerPanel.add(actionsRow);
        headerPanel.add(searchRow);

        JPanel toolbar = headerPanel;

        // ── Log text pane ─────────────────────────────────────────────────────
        logPane = new JTextPane();
        logPane.setEditable(false);
        logPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        doc = logPane.getStyledDocument();

        // Styles
        Style base = StyleContext.getDefaultStyleContext()
                .getStyle(StyleContext.DEFAULT_STYLE);

        Style tsStyle  = doc.addStyle("timestamp", base);
        StyleConstants.setForeground(tsStyle, COLOR_TIMESTAMP);

        Style infoStyle = doc.addStyle("info", base);
        StyleConstants.setForeground(infoStyle, COLOR_INFO);

        Style errorStyle = doc.addStyle("error", base);
        StyleConstants.setForeground(errorStyle, COLOR_ERROR);
        StyleConstants.setBold(errorStyle, true);

        JScrollPane scroll = new JScrollPane(logPane,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroll.setBorder(BorderFactory.createEmptyBorder());

        rootPanel.add(toolbar, BorderLayout.NORTH);
        rootPanel.add(scroll,  BorderLayout.CENTER);

        // Register with LogManager — receive new lines in real time
        logManager.addListener(this::appendLine);

        // Replay any lines already buffered before this panel was created
        String existing = logManager.getAllLogs();
        if (!existing.isBlank()) {
            for (String line : existing.split("\n")) {
                appendLineNow(line);
            }
        }
    }

    // =========================================================================
    // Append logic
    // =========================================================================

    /** Called on the EDT by LogManager for each new line. */
    private void appendLine(String line) {
        appendLineNow(line);
        if (autoScrollBox != null && autoScrollBox.isSelected()) scrollToBottom();
    }

    private void appendLineNow(String line) {
        if (line == null || line.isBlank()) return;
        try {
            // Split: "2025-03-05 21:00:00  [INFO]  message"
            // timestamp = first 19 chars, rest = level + message
            String ts  = line.length() > 19 ? line.substring(0, 19) : "";
            String rest = line.length() > 21 ? line.substring(21) : line;

            boolean isError = rest.startsWith("[ERROR]");
            String levelStyle = isError ? "error" : "info";

            doc.insertString(doc.getLength(), ts + "  ", doc.getStyle("timestamp"));
            doc.insertString(doc.getLength(), rest + "\n", doc.getStyle(levelStyle));

            lineCount++;
            if (lineCountLabel != null) lineCountLabel.setText(lineCount + " lines");
        } catch (BadLocationException ignored) {}
    }

    private void scrollToBottom() {
        logPane.setCaretPosition(doc.getLength());
    }

    // =========================================================================
    // Search
    // =========================================================================

    private void doSearch(String text) {
        Highlighter h = logPane.getHighlighter();
        h.removeAllHighlights();
        if (matchCountLabel != null) matchCountLabel.setText("");
        if (text == null || text.isBlank()) return;

        String content = logPane.getText();
        String contentLc = content.toLowerCase();
        String searchLc  = text.toLowerCase();
        int hits = 0;
        int first = -1;
        int idx = 0;
        Highlighter.HighlightPainter painter =
                new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 200, 0, 160));
        while ((idx = contentLc.indexOf(searchLc, idx)) >= 0) {
            try {
                h.addHighlight(idx, idx + text.length(), painter);
                if (first < 0) first = idx;
                hits++;
            } catch (BadLocationException ignored) {}
            idx += text.length();
        }
        if (matchCountLabel != null) {
            matchCountLabel.setText(hits > 0 ? hits + " match" + (hits == 1 ? "" : "es") : "No matches");
            matchCountLabel.setForeground(hits > 0 ? new Color(80, 180, 255) : new Color(200, 80, 80));
        }
        // Scroll to first match
        if (first >= 0) {
            try { logPane.setCaretPosition(first); } catch (Exception ignored) {}
        }
    }

    // =========================================================================
    // Actions
    // =========================================================================

    private void onClear() {
        try {
            doc.remove(0, doc.getLength());
            lineCount = 0;
            if (lineCountLabel != null) lineCountLabel.setText("0 lines");
            if (matchCountLabel != null) matchCountLabel.setText("");
            logManager.clear();
        } catch (BadLocationException ignored) {}
    }

    private void onDownload() {
        String content = logManager.getAllLogs();
        if (content.isBlank()) {
            JOptionPane.showMessageDialog(rootPanel,
                    "No log entries to save.", "Logs Empty", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String suggestedName = "secretsifter-logs-" +
                FILE_FMT.format(LocalDateTime.now()) + ".txt";

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save Logs");
        fc.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        fc.setSelectedFile(new File(suggestedName));

        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;

        File out = fc.getSelectedFile();
        if (!out.getName().toLowerCase().endsWith(".txt"))
            out = new File(out.getAbsolutePath() + ".txt");

        try (PrintWriter pw = new PrintWriter(new FileWriter(out, StandardCharsets.UTF_8))) {
            pw.println("SecretSifter Log Export — " + LocalDateTime.now());
            pw.println("=".repeat(72));
            pw.println(content);
            JOptionPane.showMessageDialog(rootPanel,
                    "Logs saved to:\n" + out.getAbsolutePath(),
                    "Saved", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
