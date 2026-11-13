package com.secretscanner;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.plaf.LayerUI;
import java.awt.*;
import java.awt.image.BaseMultiResolutionImage;
import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP SecretSifter branding: name, project link, the OWASP logo in the extension header, a faint
 * watermark over every SecretSifter page, the load-time banner, and the logo used in HTML reports.
 *
 * Logos ship in two inks (dark for light themes, light for dark themes) at 1x and 2x; the ink is
 * chosen from Burp's current theme at paint time, so switching Burp's theme needs no reload.
 */
public final class Branding {

    static final String NAME        = "OWASP SecretSifter (Burp MCP)";
    static final String TAGLINE     = "Runtime credential exposure detection";
    static final String PROJECT_URL = "https://owasp.org/www-project-secretsifter/";

    private static final Map<String, Image> IMAGES = new ConcurrentHashMap<>();

    private Branding() {}

    /** True when Burp's look and feel has a dark panel background. */
    static boolean darkTheme() {
        Color bg = UIManager.getColor("Panel.background");
        if (bg == null) return false;
        double lum = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255.0;
        return lum < 0.5;
    }

    /** "logo" or "mark" in the ink that suits the current theme; null if the resource is missing. */
    static Image image(String kind) {
        String name = kind + (darkTheme() ? "-light" : "-dark");
        return IMAGES.computeIfAbsent(name, Branding::load);
    }

    private static Image load(String name) {
        BufferedImage x1 = read("/branding/" + name + ".png");
        BufferedImage x2 = read("/branding/" + name + "@2x.png");
        if (x1 == null) return x2;
        return x2 == null ? x1 : new BaseMultiResolutionImage(x1, x2);
    }

    private static BufferedImage read(String path) {
        try (InputStream in = Branding.class.getResourceAsStream(path)) {
            return in == null ? null : ImageIO.read(in);
        } catch (Exception e) {
            return null;
        }
    }

    /** The SecretSifter suite tab content: an OWASP header bar above {@code content}. */
    static JComponent wrap(JComponent content) {
        JPanel root = new JPanel(new BorderLayout());
        root.add(header(), BorderLayout.NORTH);
        root.add(content, BorderLayout.CENTER);
        return root;
    }

    /**
     * Returns {@code scroll} unchanged. The OWASP mark lives in the header only — per user feedback a
     * per-box watermark in every text area looked awkward, so boxes are left clean. Kept as a
     * pass-through so call sites need not change if the policy changes again.
     */
    static JComponent watermarkInBox(JScrollPane scroll) {
        return scroll;
    }

    private static JComponent header() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")));
        bar.add(new LogoView("logo", 24));
        bar.add(projectLink("OWASP SecretSifter"));
        JLabel url = new JLabel(PROJECT_URL.replaceFirst("^https://", "").replaceFirst("/$", ""));
        url.setForeground(UIManager.getColor("Label.disabledForeground"));
        bar.add(url);
        return bar;
    }

    /** Bold label that opens the OWASP project page in the browser; underlined on hover. */
    private static JLabel projectLink(String text) {
        JLabel link = new JLabel(text);
        Font bold = link.getFont().deriveFont(Font.BOLD, link.getFont().getSize2D() + 3f);
        link.setFont(bold);
        link.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        link.setToolTipText(NAME + " — " + PROJECT_URL);
        link.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) { openProjectPage(); }
            @Override public void mouseEntered(java.awt.event.MouseEvent e) {
                link.setFont(bold.deriveFont(Map.of(java.awt.font.TextAttribute.UNDERLINE,
                        java.awt.font.TextAttribute.UNDERLINE_ON)));
            }
            @Override public void mouseExited(java.awt.event.MouseEvent e) { link.setFont(bold); }
        });
        return link;
    }

    private static void openProjectPage() {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE))
                Desktop.getDesktop().browse(java.net.URI.create(PROJECT_URL));
        } catch (Exception ignored) {
            // no browser available: the URL is shown next to the link
        }
    }

    /** Draws the themed logo at a fixed height. */
    private static final class LogoView extends JComponent {
        private final String kind;
        private final int height;

        LogoView(String kind, int height) {
            this.kind = kind;
            this.height = height;
            setToolTipText(NAME + " — " + PROJECT_URL);
        }

        @Override public Dimension getPreferredSize() {
            Image img = image(kind);
            if (img == null) return new Dimension(0, height);
            int w = img.getWidth(null), h = img.getHeight(null);
            if (img instanceof BaseMultiResolutionImage m) {
                Image base = m.getResolutionVariants().get(0);
                w = base.getWidth(null); h = base.getHeight(null);
            }
            return new Dimension(h > 0 ? w * height / h : height, height);
        }

        @Override protected void paintComponent(Graphics g) {
            Image img = image(kind);
            if (img == null) return;
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            Dimension d = getPreferredSize();
            g2.drawImage(img, 0, (getHeight() - d.height) / 2, d.width, d.height, null);
            g2.dispose();
        }
    }

    /**
     * Faint OWASP mark painted over a scroll pane, centred in its visible area and scaled to fit
     * inside it (up to {@value #MAX_HEIGHT} px tall); clipped to the box, mouse events pass through.
     */
    private static final class WatermarkUI extends LayerUI<JComponent> {
        private static final int MAX_HEIGHT = 320;

        @Override public void paint(Graphics g, JComponent c) {
            super.paint(g, c);
            Image img = image("mark");
            if (img == null || !(c instanceof JLayer<?> layer) || !(layer.getView() instanceof JScrollPane sp)) return;
            JViewport vp = sp.getViewport();
            Rectangle area = SwingUtilities.convertRectangle(vp.getParent(), vp.getBounds(), c);
            int h = Math.min(MAX_HEIGHT, (int) (Math.min(area.width * 256 / 280, area.height) * 0.7));
            if (h < 60) return;                                       // too small to read: skip
            int w = h * 280 / 256;                                    // mark aspect ratio
            Graphics2D g2 = (Graphics2D) g.create();
            g2.clip(area);
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.05f));
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            g2.drawImage(img, area.x + (area.width - w) / 2, area.y + (area.height - h) / 2, w, h, null);
            g2.dispose();
        }
    }

    /** Banner printed to Extensions > Output when the extension loads: OWASP / SecretSifter in large letters. */
    static String banner(String edition) {
        String rule = "-".repeat(64);
        String art = resourceText("/branding/banner.txt").stripTrailing();
        return "\n" + rule + "\n"
                + (art.isEmpty() ? "   " + NAME : art) + "\n"
                + rule + "\n"
                + "   " + NAME + "  v" + SecretSifterVersion.VALUE + "  (" + edition + ")\n"
                + "   " + TAGLINE + "\n"
                + "   An OWASP Foundation project  ·  " + PROJECT_URL + "\n"
                + rule + "\n";
    }

    /** OWASP SecretSifter combo logo as an inline &lt;img&gt; for HTML reports; "" if unavailable. */
    static String logoSvg(boolean lightInk) {
        String uri = brandmarkUri();
        return uri.isEmpty() ? "" : "<img src=\"" + uri + "\" role=\"img\" alt=\"OWASP SecretSifter\">";
    }

    /** The OWASP SecretSifter combo logo as a data: URI, for the report watermark; "" if unavailable. */
    static String markDataUri() {
        return brandmarkUri();
    }

    /** The combo brandmark PNG as a data: URI; "" if the resource is missing. */
    private static String brandmarkUri() {
        try (InputStream in = Branding.class.getResourceAsStream("/branding/brandmark.png")) {
            return in == null ? "" : "data:image/png;base64,"
                    + java.util.Base64.getEncoder().encodeToString(in.readAllBytes());
        } catch (Exception e) {
            return "";
        }
    }

    private static String resourceText(String path) {
        try (InputStream in = Branding.class.getResourceAsStream(path)) {
            return in == null ? "" : new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }
}
