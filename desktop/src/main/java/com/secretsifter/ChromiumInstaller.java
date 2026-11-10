package com.secretsifter;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Checks for and installs Playwright's bundled Chromium browser.
 *
 * Primary method: direct HTTP download (no subprocess, works in all environments).
 * Fallback: subprocess via {@code com.microsoft.playwright.CLI} (for environments
 * where direct download is blocked but subprocess is available).
 */
public class ChromiumInstaller {

    /**
     * Returns the path to a system-installed Microsoft Edge executable, or null if not found.
     * Used as a fallback on Windows when Chromium has not been downloaded.
     */
    public static String findSystemEdge() {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return null;
        // Primary: registry (authoritative on any Windows setup)
        try {
            Process p = new ProcessBuilder("reg", "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
                    "/ve").start();
            try (java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.contains("REG_SZ")) {
                        String path = line.substring(line.lastIndexOf("REG_SZ") + 6).trim();
                        if (new File(path).exists()) return path;
                    }
                }
            }
            p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) {}
        // Fallback: hardcoded default install paths
        String[] candidates = {
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
        };
        for (String path : candidates) {
            if (new File(path).exists()) return path;
        }
        return null;
    }

    /**
     * Returns true if Playwright's Chromium is present in the standard cache directory.
     */
    public static boolean isInstalled() {
        File cache = playwrightCacheDir();
        if (!cache.isDirectory()) return false;
        File[] dirs = cache.listFiles(f -> f.isDirectory() && f.getName().startsWith("chromium-"));
        return dirs != null && dirs.length > 0;
    }

    /**
     * Downloads and installs Chromium.
     * Tries direct HTTP download first; falls back to subprocess if that fails.
     *
     * @param cancel set {@code true} to abort
     * @param onLine receives status lines; called from worker threads
     * @return 0 on success, -1 on failure/cancel
     */
    public static int install(AtomicBoolean cancel, Consumer<String> onLine) {
        File debugLog = new File(System.getProperty("java.io.tmpdir"),
                "secretsifter-chromium-debug.log");
        dbg(debugLog, "install() called");

        // ── Primary: direct HTTP download ──────────────────────────────────
        int result = downloadDirect(cancel, onLine, debugLog);
        if (result == 0 || cancel.get()) return result;

        // ── Fallback: subprocess ────────────────────────────────────────────
        dbg(debugLog, "direct download failed, trying subprocess fallback");
        onLine.accept("Direct download failed, trying alternate method…");
        return installViaSubprocess(cancel, onLine, debugLog);
    }

    // ── Direct HTTP download ──────────────────────────────────────────────────

    private static int downloadDirect(AtomicBoolean cancel,
                                      Consumer<String> onLine, File debugLog) {
        try {
            String buildNum = detectChromiumBuild();
            dbg(debugLog, "chromium build=" + buildNum);

            String platform = chromiumPlatform();
            String downloadUrl = "https://playwright.azureedge.net/builds/chromium/"
                    + buildNum + "/" + platform;
            dbg(debugLog, "download url=" + downloadUrl);

            File destRoot = playwrightCacheDir();
            destRoot.mkdirs();
            File chromiumDir = new File(destRoot, "chromium-" + buildNum);

            onLine.accept("Downloading Chromium " + buildNum + " (~135 MiB)…");

            // Download zip to a temp file
            File tempZip = File.createTempFile("playwright-chromium-", ".zip");
            dbg(debugLog, "temp zip=" + tempZip);
            try {
                HttpURLConnection conn = openWithRedirects(downloadUrl);
                long total = conn.getContentLengthLong();
                dbg(debugLog, "content-length=" + total);

                try (InputStream in = conn.getInputStream();
                     FileOutputStream fos = new FileOutputStream(tempZip)) {
                    byte[] buf = new byte[65536];
                    long done = 0;
                    int lastPct = -1;
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        if (cancel.get()) return -1;
                        fos.write(buf, 0, n);
                        done += n;
                        if (total > 0) {
                            int pct = (int) (done * 100 / total);
                            if (pct != lastPct && pct % 5 == 0) {
                                lastPct = pct;
                                onLine.accept("Downloading Chromium "
                                        + pct + "%  ("
                                        + (done / 1048576) + " / "
                                        + (total / 1048576) + " MiB)");
                            }
                        }
                    }
                    dbg(debugLog, "download complete, " + done + " bytes");
                } finally {
                    conn.disconnect();
                }

                if (cancel.get()) return -1;

                // Extract
                onLine.accept("Extracting Chromium…");
                dbg(debugLog, "extracting to " + chromiumDir);
                extractZip(tempZip, destRoot, chromiumDir, cancel, debugLog);

            } finally {
                tempZip.delete();
            }

            if (cancel.get()) return -1;

            if (!chromiumDir.isDirectory()) {
                dbg(debugLog, "ERROR: chromium dir not created after extract");
                onLine.accept("Extraction error: target directory missing.");
                return -1;
            }

            onLine.accept("Chromium installed successfully.");
            dbg(debugLog, "install complete: " + chromiumDir);
            return 0;

        } catch (Exception e) {
            dbg(debugLog, "downloadDirect exception: " + e.getClass().getName()
                    + ": " + e.getMessage());
            return -1;
        }
    }

    /**
     * Opens a URL following HTTP redirects (Azure CDN uses them).
     */
    private static HttpURLConnection openWithRedirects(String urlStr) throws IOException {
        for (int i = 0; i < 10; i++) {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(30_000);
            conn.setReadTimeout(120_000);
            conn.setInstanceFollowRedirects(false);
            int code = conn.getResponseCode();
            if (code == HttpURLConnection.HTTP_MOVED_TEMP
                    || code == HttpURLConnection.HTTP_MOVED_PERM
                    || code == 307 || code == 308) {
                urlStr = conn.getHeaderField("Location");
                conn.disconnect();
                continue;
            }
            return conn;
        }
        throw new IOException("Too many redirects for " + urlStr);
    }

    /**
     * Extracts the Chromium zip into the Playwright cache directory.
     *
     * Playwright zips may have entries prefixed with "chromium-NNNN/" or bare
     * paths like "chrome-win/…". We detect the prefix automatically and always
     * end up with  {@code destRoot/chromium-NNNN/} on disk.
     */
    private static void extractZip(File zipFile, File destRoot, File chromiumDir,
                                   AtomicBoolean cancel, File debugLog) throws Exception {
        // Peek at the first entry to detect prefix style
        String stripPrefix = null;
        try (ZipInputStream peek = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry first = peek.getNextEntry();
            if (first != null) {
                String name = first.getName();
                int slash = name.indexOf('/');
                String top = slash >= 0 ? name.substring(0, slash + 1) : "";
                if (top.startsWith("chromium-")) {
                    // Zip has entries like "chromium-1124/chrome-win/..."
                    // Extract directly into destRoot (the chromium-1124 dir appears naturally)
                    stripPrefix = null;
                    dbg(debugLog, "zip has chromium- prefix, extracting to destRoot");
                } else {
                    // Zip has bare entries like "chrome-win/..."
                    // Extract into chromiumDir so prefix is added
                    stripPrefix = "";
                    dbg(debugLog, "zip has no prefix, extracting into chromiumDir");
                }
            }
        }

        File extractTarget = (stripPrefix != null) ? chromiumDir : destRoot;
        extractTarget.mkdirs();

        byte[] buf = new byte[65536];
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (cancel.get()) break;
                File dest = new File(extractTarget, entry.getName());
                // Zip-slip guard
                if (!dest.getCanonicalPath().startsWith(extractTarget.getCanonicalPath())) {
                    zis.closeEntry();
                    continue;
                }
                if (entry.isDirectory()) {
                    dest.mkdirs();
                } else {
                    dest.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(dest)) {
                        int n;
                        while ((n = zis.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    // Mark executables on non-Windows
                    String name = dest.getName();
                    if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
                        if (!name.contains(".") || name.endsWith(".sh")) {
                            dest.setExecutable(true, false);
                        }
                    }
                }
                zis.closeEntry();
            }
        }
    }

    /** Detects the Chromium build number from Playwright's bundled browser manifest. */
    private static String detectChromiumBuild() {
        // Try reading browsers.json from the Playwright driver package (bundled in jar)
        String[] resourcePaths = {
            "/driver/package/browsers.json",
            "/playwright/driver/package/browsers.json",
            "/com/microsoft/playwright/driver/package/browsers.json"
        };
        for (String path : resourcePaths) {
            try (InputStream is = ChromiumInstaller.class.getResourceAsStream(path)) {
                if (is == null) continue;
                String json = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                // Match: "name": "chromium", ... "revision": "NNNN"
                Matcher m = Pattern.compile(
                    "\"name\"\\s*:\\s*\"chromium\"[^}]{0,200}?\"revision\"\\s*:\\s*\"(\\d+)\"",
                    Pattern.DOTALL).matcher(json);
                if (m.find()) return m.group(1);
            } catch (Exception ignored) {}
        }
        return "1124"; // default for Playwright 1.45.0
    }

    /** Returns the platform-specific Chromium zip file name. */
    private static String chromiumPlatform() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        if (os.contains("win"))  return "chromium-win64.zip";
        if (os.contains("mac"))  return arch.contains("aarch64")
                ? "chromium-mac-arm64.zip" : "chromium-mac.zip";
        return "chromium-linux.zip";
    }

    // ── Subprocess fallback ───────────────────────────────────────────────────

    private static int installViaSubprocess(AtomicBoolean cancel,
                                            Consumer<String> onLine, File debugLog) {
        try {
            String javaExe = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
            if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
                javaExe += ".exe";
            }
            File javaFile = new File(javaExe);
            if (!javaFile.exists()) {
                javaExe = "java";
            } else if (!javaFile.canExecute()) {
                javaFile.setExecutable(true, false);
            }

            String classpath = resolveClasspath();
            dbg(debugLog, "subprocess java=" + javaExe + " cp=" + classpath);

            ProcessBuilder pb = new ProcessBuilder(
                    javaExe, "-cp", classpath,
                    "com.microsoft.playwright.CLI", "install", "chromium");
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            dbg(debugLog, "subprocess PID=" + proc.pid());

            Thread reader = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(proc.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        onLine.accept(line);
                        if (cancel.get()) break;
                    }
                } catch (IOException ignored) {}
            }, "SecretSifter-ChromiumReader");
            reader.setDaemon(true);
            reader.start();

            // Wait up to 15 minutes
            long deadline = System.currentTimeMillis() + 15 * 60 * 1000L;
            while (!proc.waitFor(250, TimeUnit.MILLISECONDS)) {
                if (cancel.get()) { proc.destroyForcibly(); return -1; }
                if (System.currentTimeMillis() > deadline) {
                    proc.destroyForcibly();
                    dbg(debugLog, "subprocess timeout");
                    onLine.accept("Chromium install timed out.");
                    return -1;
                }
            }
            reader.join(3000);
            int code = cancel.get() ? -1 : proc.exitValue();
            dbg(debugLog, "subprocess exitCode=" + code);
            return code;

        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            dbg(debugLog, "subprocess exception: " + msg);
            onLine.accept("Cannot launch Java subprocess: " + msg);
            return -1;
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Returns the Playwright browser cache directory for the current OS. */
    static File playwrightCacheDir() {
        String os   = System.getProperty("os.name", "").toLowerCase();
        String home = System.getProperty("user.home");
        if (os.contains("win")) {
            String local = System.getenv("LOCALAPPDATA");
            return new File(local != null ? local : home, "ms-playwright");
        }
        if (os.contains("mac")) {
            return new File(home, "Library/Caches/ms-playwright");
        }
        String xdg = System.getenv("XDG_CACHE_HOME");
        return new File(xdg != null ? xdg : home + "/.cache", "ms-playwright");
    }

    private static String resolveClasspath() {
        try {
            java.security.CodeSource cs =
                ChromiumInstaller.class.getProtectionDomain().getCodeSource();
            if (cs != null && cs.getLocation() != null) {
                File jar = new File(cs.getLocation().toURI());
                if (jar.isFile()) return jar.getAbsolutePath();
            }
        } catch (URISyntaxException ignored) {}
        String cp = System.getProperty("java.class.path", "");
        if (cp.isEmpty()) return cp;
        return Arrays.stream(cp.split(File.pathSeparator))
                .map(p -> new File(p).getAbsolutePath())
                .collect(Collectors.joining(File.pathSeparator));
    }

    private static void dbg(File f, String msg) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(f, true))) {
            pw.println(new java.util.Date() + "  " + msg);
        } catch (IOException ignored) {}
    }
}
