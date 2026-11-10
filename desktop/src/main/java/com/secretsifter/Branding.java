package com.secretsifter;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.InputStream;

/**
 * OWASP SecretSifter branding for the desktop app: a faint OWASP owl mark painted over the
 * background of each main page. The mark lives on the page background (not in every box — a
 * per-box watermark was rejected as awkward) and in the headers / About dialog / HTML report.
 */
final class Branding {

    static final String NAME        = "OWASP SecretSifter";
    static final String PROJECT_URL = "https://owasp.org/www-project-secretsifter/";

    private static BufferedImage markImg;      // loaded lazily; null if the resource is missing
    private static boolean markLoaded;

    private Branding() {}

    private static BufferedImage mark() {
        if (!markLoaded) {
            markLoaded = true;
            try (InputStream in = Branding.class.getResourceAsStream("/branding/watermark.png")) {
                markImg = in == null ? null : ImageIO.read(in);
            } catch (Exception e) {
                markImg = null;
            }
        }
        return markImg;
    }

    /**
     * Wraps {@code content} so a faint, centred OWASP owl is painted over its background.
     * Mouse events pass straight through to {@code content}; the overlay only paints.
     */
    static JComponent watermark(JComponent content) {
        return new WatermarkPanel(content);
    }

    /** Pass-through kept for parity with the Burp edition's call sites (boxes are left clean). */
    static JComponent watermarkInBox(JScrollPane scroll) {
        return scroll;
    }

    /**
     * Holds {@code content} full-size and paints a faint, centred OWASP owl on top after the
     * content has painted. Transparent to interaction — all components inside stay fully usable.
     */
    private static final class WatermarkPanel extends JPanel {
        private static final int MAX_HEIGHT = 420;

        WatermarkPanel(JComponent content) {
            super(new BorderLayout());
            setOpaque(false);
            add(content, BorderLayout.CENTER);
        }

        @Override public void paint(Graphics g) {
            super.paint(g);                                   // paint the page content first
            BufferedImage img = mark();
            if (img == null) return;
            int side = Math.min(getWidth(), getHeight());
            int h = Math.min(MAX_HEIGHT, (int) (side * 0.60));
            if (h < 80) return;                               // too small to read: skip
            int w = h * img.getWidth() / img.getHeight();
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.12f));
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            g2.drawImage(img, (getWidth() - w) / 2, (getHeight() - h) / 2, w, h, null);
            g2.dispose();
        }
    }
}
