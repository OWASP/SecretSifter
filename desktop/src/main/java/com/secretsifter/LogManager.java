package com.secretsifter;

import javax.swing.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Thread-safe logger that implements {@link AppLogger}, buffers all log lines
 * with timestamps, and notifies registered UI listeners on the EDT.
 *
 * Acts as the single AppLogger passed to SecretScanner, HttpFetcher,
 * BulkScanPanel, and PlaywrightCrawler — everything routes here.
 */
public class LogManager implements AppLogger {

    private static final int MAX_LINES = 20_000;
    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** All buffered log lines (access synchronized on itself). */
    private final List<String> buffer = new ArrayList<>(1024);

    /** EDT listeners notified whenever a new line is appended. */
    private final CopyOnWriteArrayList<Consumer<String>> listeners = new CopyOnWriteArrayList<>();

    // ── AppLogger implementation ──────────────────────────────────────────────

    @Override
    public void logToOutput(String msg) {
        append("[INFO]  " + msg);
    }

    @Override
    public void logToError(String msg) {
        append("[ERROR] " + msg);
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Register a listener that receives each new timestamped log line on the EDT. */
    public void addListener(Consumer<String> listener) {
        listeners.add(listener);
    }

    /** Returns a snapshot of all buffered log lines joined by newlines. */
    public String getAllLogs() {
        synchronized (buffer) {
            return String.join("\n", buffer);
        }
    }

    /** Clears the internal log buffer (does NOT notify listeners). */
    public void clear() {
        synchronized (buffer) {
            buffer.clear();
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private void append(String rawMsg) {
        String line = FMT.format(LocalDateTime.now()) + "  " + rawMsg;

        synchronized (buffer) {
            if (buffer.size() >= MAX_LINES) {
                // Drop oldest 10 % to avoid unbounded growth
                buffer.subList(0, MAX_LINES / 10).clear();
                buffer.add(FMT.format(LocalDateTime.now()) + "  [WARN]  Log buffer trimmed — oldest "
                        + (MAX_LINES / 10) + " lines removed to free memory.");
            }
            buffer.add(line);
        }

        // Notify listeners on the EDT
        if (!listeners.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                for (Consumer<String> l : listeners) {
                    try { l.accept(line); } catch (Exception ignored) {}
                }
            });
        }
    }
}
