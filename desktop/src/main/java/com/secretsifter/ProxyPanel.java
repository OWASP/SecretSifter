package com.secretsifter;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * "Proxy" tab — run a built-in HTTP/HTTPS MITM proxy that intercepts all browser
 * traffic and scans every response for secrets in real-time, exactly like Burp Suite.
 *
 * Workflow:
 *  1. Click "Start Proxy" (default port 8888).
 *  2. Click "Export CA Certificate" → save SecretSifterCA.crt.
 *  3. Import the .crt into your browser's trusted root CA store.
 *  4. Set your browser's HTTP/HTTPS proxy to localhost:PORT.
 *  5. Browse your application — all findings appear in the Scan tab.
 */
public class ProxyPanel {

    // ── Swing controls ────────────────────────────────────────────────────────
    private JPanel      rootPanel;
    private JButton     startStopBtn;
    private JButton     exportCaBtn;
    private JSpinner    portSpinner;
    private JLabel      statusLabel;
    private JLabel      interceptedLabel;
    private JLabel      findingsLabel;
    private JTextArea   instructionsArea;

    // ── State ─────────────────────────────────────────────────────────────────
    private final SecretScanner           scanner;
    private final AppLogger               logger;
    private final Consumer<List<SecretFinding>> onFindings;
    private       CaptureStore            captureStore;

    private ProxyListener        listener;
    private CertificateAuthority ca;

    /** Optional — lets proxied req/resp show up in the Scan-tab Details side-panel. */
    public void setCaptureStore(CaptureStore store) { this.captureStore = store; }
    private final AtomicInteger  interceptedCount = new AtomicInteger();
    private final AtomicInteger  findingsCount    = new AtomicInteger();

    public ProxyPanel(SecretScanner scanner, AppLogger logger,
                      Consumer<List<SecretFinding>> onFindings) {
        this.scanner    = scanner;
        this.logger     = logger;
        this.onFindings = onFindings;

        if (SwingUtilities.isEventDispatchThread()) buildUi();
        else try { SwingUtilities.invokeAndWait(this::buildUi); }
             catch (Exception e) { SwingUtilities.invokeLater(this::buildUi); }
    }

    public JPanel getPanel() { return rootPanel; }

    public void shutdown() {
        if (listener != null && listener.isRunning()) stopProxy();
    }

    // =========================================================================
    // UI
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(8, 8));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        // ── Controls row ──────────────────────────────────────────────────────
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
        controls.setBorder(new TitledBorder("Proxy Settings"));

        controls.add(new JLabel("Port:"));
        portSpinner = new JSpinner(new SpinnerNumberModel(8888, 1024, 65535, 1));
        // Strip locale grouping ("8,888" → "8888") so users can copy the port into
        // browser proxy fields without confusion.  Browsers parse "8,888" as port 8.
        JSpinner.NumberEditor portEditor = new JSpinner.NumberEditor(portSpinner, "#");
        portSpinner.setEditor(portEditor);
        portSpinner.setPreferredSize(new Dimension(80, 26));
        controls.add(portSpinner);

        startStopBtn = new JButton("Start Proxy");
        startStopBtn.addActionListener(e -> toggleProxy());
        controls.add(startStopBtn);

        exportCaBtn = new JButton("Export CA Certificate…");
        exportCaBtn.setEnabled(false);
        exportCaBtn.addActionListener(e -> exportCa());
        controls.add(exportCaBtn);

        statusLabel = new JLabel("  Stopped");
        statusLabel.setForeground(new Color(180, 60, 60));
        controls.add(statusLabel);

        // ── Stats row ─────────────────────────────────────────────────────────
        JPanel stats = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 2));
        interceptedLabel = new JLabel("Requests intercepted: 0");
        findingsLabel    = new JLabel("Findings captured: 0");
        stats.add(interceptedLabel);
        stats.add(findingsLabel);

        JPanel top = new JPanel(new BorderLayout());
        top.add(controls, BorderLayout.NORTH);
        top.add(stats,    BorderLayout.SOUTH);

        // ── Instructions panel ────────────────────────────────────────────────
        instructionsArea = new JTextArea(buildInstructions(8888));
        instructionsArea.setEditable(false);
        instructionsArea.setLineWrap(true);
        instructionsArea.setWrapStyleWord(true);
        instructionsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        instructionsArea.setBackground(UIManager.getColor("Panel.background"));
        JScrollPane scroll = new JScrollPane(instructionsArea);
        scroll.setBorder(new TitledBorder("Setup Instructions"));

        rootPanel.add(top,    BorderLayout.NORTH);
        rootPanel.add(scroll, BorderLayout.CENTER);
    }

    // =========================================================================
    // Proxy lifecycle
    // =========================================================================

    private void toggleProxy() {
        if (listener != null && listener.isRunning()) stopProxy();
        else startProxy();
    }

    private void startProxy() {
        int port = (int) portSpinner.getValue();
        startStopBtn.setEnabled(false);
        portSpinner.setEnabled(false);

        new Thread(() -> {
            try {
                ca       = new CertificateAuthority();
                listener = new ProxyListener(port, ca, scanner, (findings, url) -> {
                    int rCount = interceptedCount.incrementAndGet();
                    int fCount = findingsCount.addAndGet(findings.size());
                    SwingUtilities.invokeLater(() -> {
                        interceptedLabel.setText("Requests intercepted: " + rCount);
                        findingsLabel   .setText("Findings captured: "    + fCount);
                    });
                    onFindings.accept(findings);
                }, logger);
                listener.setCaptureStore(captureStore);
                listener.start();

                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("  Running on port " + port);
                    statusLabel.setForeground(new Color(40, 170, 70));
                    startStopBtn.setText("Stop Proxy");
                    startStopBtn.setEnabled(true);
                    exportCaBtn.setEnabled(true);
                    portSpinner.setEnabled(false);
                    instructionsArea.setText(buildInstructions(port));
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("  Failed to start");
                    statusLabel.setForeground(new Color(210, 50, 50));
                    startStopBtn.setText("Start Proxy");
                    startStopBtn.setEnabled(true);
                    portSpinner.setEnabled(true);
                    JOptionPane.showMessageDialog(rootPanel,
                            "Could not start proxy on port " + port + ":\n" + ex.getMessage(),
                            "Proxy Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "proxy-start").start();
    }

    private void stopProxy() {
        if (listener != null) { listener.stop(); listener = null; }
        ca = null;
        statusLabel.setText("  Stopped");
        statusLabel.setForeground(new Color(180, 60, 60));
        startStopBtn.setText("Start Proxy");
        portSpinner.setEnabled(true);
        exportCaBtn.setEnabled(false);
    }

    // ── CA export ─────────────────────────────────────────────────────────────

    private void exportCa() {
        if (ca == null) return;
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("SecretSifterCA.crt"));
        fc.setDialogTitle("Export CA Certificate");
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        try {
            Files.write(fc.getSelectedFile().toPath(), ca.getCaCertDer());
            JOptionPane.showMessageDialog(rootPanel,
                    "Exported to: " + fc.getSelectedFile().getAbsolutePath() + "\n\n" +
                    "Install this in your browser's Trusted Root CA store to enable HTTPS scanning.\n" +
                    "  Chrome/Edge: Settings → Privacy & security → Security → Manage certificates\n" +
                    "               → Trusted Root Certification Authorities → Import\n" +
                    "  Firefox:     about:preferences#privacy → View Certificates\n" +
                    "               → Authorities → Import → trust for websites",
                    "CA Certificate Exported", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Export failed: " + e.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // =========================================================================
    // Instructions text
    // =========================================================================

    private static String buildInstructions(int port) {
        return
"HOW TO USE THE BUILT-IN PROXY\n" +
"═══════════════════════════════════════════════════════════════\n" +
"\n" +
"The SecretSifter proxy intercepts ALL HTTP and HTTPS traffic from your browser,\n" +
"scanning every response for secrets in real-time — exactly like Burp Suite.\n" +
"Unlike the browser crawler, the proxy sees AUTHENTICATED traffic, lazy-loaded\n" +
"chunks, Bearer/JWT tokens, and any secrets only served after login.\n" +
"\n" +
"STEP 1 — Start the Proxy\n" +
"  • Choose a port (default: 8888) and click \"Start Proxy\".\n" +
"  • A new CA keypair is generated automatically.\n" +
"\n" +
"STEP 2 — Export and Install the CA Certificate (for HTTPS)\n" +
"  • Click \"Export CA Certificate…\" → save SecretSifterCA.crt anywhere.\n" +
"  • Chrome/Edge: Settings → Privacy & security → Security\n" +
"                → Manage certificates → Trusted Root Certification Authorities\n" +
"                → Import → select SecretSifterCA.crt → OK\n" +
"  • Firefox: about:preferences#privacy → View Certificates\n" +
"             → Authorities tab → Import → select the .crt → trust for websites\n" +
"  • You only need to do this ONCE per proxy session.\n" +
"    The CA cert changes each time you start the proxy, so re-import if you restart.\n" +
"\n" +
"STEP 3 — Configure Your Browser to Use the Proxy\n" +
"  • Set your browser's HTTP and HTTPS proxy to: localhost : " + port + "\n" +
"  • Chrome/Edge (Windows): Settings → System → Open your computer's proxy settings\n" +
"                           → Manual setup → Address: localhost, Port: " + port + "\n" +
"  • Firefox: about:preferences#general → Network Settings → Manual proxy\n" +
"             → HTTP Proxy: localhost, Port: " + port + "\n" +
"  • Tip: use the FoxyProxy browser extension to switch the proxy on/off easily.\n" +
"\n" +
"STEP 4 — Browse Your Application\n" +
"  • Log in to your target application as a real user.\n" +
"  • Navigate all pages, features, and API flows you want to scan.\n" +
"  • SecretSifter scans every response in real-time.\n" +
"  • Findings appear immediately in the Scan tab.\n" +
"\n" +
"WHAT THE PROXY CAPTURES (vs. the browser crawler)\n" +
"  ✔  Bearer tokens and JWTs in Authorization request headers\n" +
"  ✔  Secrets in responses only served to authenticated users\n" +
"  ✔  Dynamically generated or server-rendered config blobs\n" +
"  ✔  Lazy-loaded Angular/React chunks triggered by route navigation\n" +
"  ✔  Cross-origin API responses (Azure APIM, microservices, etc.)\n" +
"  ✔  POST/PUT request bodies with credentials\n" +
"\n" +
"NOTE: The CA is regenerated fresh each time you click \"Start Proxy\".\n" +
"If you stop and restart, re-export and re-import the new CA certificate.\n";
    }
}
