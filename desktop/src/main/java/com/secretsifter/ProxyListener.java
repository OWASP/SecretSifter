package com.secretsifter;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/**
 * Built-in HTTP/HTTPS MITM proxy that scans every intercepted response for secrets.
 *
 * How it works:
 *  1. Listen on a local port (default 8888).
 *  2. HTTP plain traffic: forward the request to the real server, scan the response body
 *     and any credential request headers, relay both sides transparently.
 *  3. HTTPS (CONNECT tunnel): send "200 Connection established", wrap the client
 *     socket in an SSLSocket presenting a per-host cert signed by our CA, then
 *     handle the decrypted inner request exactly like plain HTTP.
 *
 * Configure your browser to use http://localhost:PORT as its HTTP+HTTPS proxy,
 * then import the exported CA certificate into the browser's trust store once.
 */
public class ProxyListener {

    private final int                                    port;
    private final CertificateAuthority                   ca;
    private final SecretScanner                          scanner;
    private final BiConsumer<List<SecretFinding>, String> onFindings;
    private final AppLogger                              logger;
    private       CaptureStore                           captureStore;   // optional

    private ServerSocket          serverSocket;
    private final AtomicBoolean   running = new AtomicBoolean(false);
    private final ExecutorService pool    = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "proxy-worker");
        t.setDaemon(true);
        return t;
    });

    /** Optional — attach a CaptureStore so the Details side-panel can show req/resp. */
    public void setCaptureStore(CaptureStore store) { this.captureStore = store; }

    /** Trust-all SSL context used when connecting outbound to target servers. */
    private static final SSLContext TRUST_ALL_CTX;
    static {
        try {
            TRUST_ALL_CTX = SSLContext.getInstance("TLS");
            TRUST_ALL_CTX.init(null, new TrustManager[]{
                    new X509ExtendedTrustManager() {
                        @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
                        @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
                        @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) {}
                        @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) {}
                        @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) {}
                        @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) {}
                        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }}, new SecureRandom());
        } catch (Exception ex) { throw new ExceptionInInitializerError(ex); }
    }

    public ProxyListener(int port, CertificateAuthority ca, SecretScanner scanner,
                          BiConsumer<List<SecretFinding>, String> onFindings, AppLogger logger) {
        this.port       = port;
        this.ca         = ca;
        this.scanner    = scanner;
        this.onFindings = onFindings;
        this.logger     = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        running.set(true);
        Thread acceptor = new Thread(this::acceptLoop, "proxy-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
        logger.logToOutput("[Proxy] Listening on port " + port);
    }

    public void stop() {
        running.set(false);
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        pool.shutdownNow();
        logger.logToOutput("[Proxy] Stopped");
    }

    public boolean isRunning() { return running.get(); }
    public int     getPort()   { return port; }

    // ── Accept loop ───────────────────────────────────────────────────────────

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = serverSocket.accept();
                client.setSoTimeout(30_000);
                pool.submit(() -> handleClient(client));
            } catch (IOException e) {
                if (running.get()) logger.logToError("[Proxy] Accept error: " + e.getMessage());
            }
        }
    }

    // ── Per-connection handler ────────────────────────────────────────────────

    private void handleClient(Socket client) {
        try (client) {
            InputStream  in  = client.getInputStream();
            OutputStream out = client.getOutputStream();

            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isBlank()) return;

            Map<String, String> headers = readHeaders(in);
            String[] parts  = requestLine.split(" ", 3);
            if (parts.length < 2) return;
            String method = parts[0].toUpperCase(Locale.ROOT);
            String target = parts[1];

            if ("CONNECT".equals(method)) {
                handleConnect(client, in, out, target);
            } else {
                handleHttp(in, out, requestLine, headers, method, target, false);
            }
        } catch (Exception ignored) {}
    }

    // ── HTTPS CONNECT tunnel ──────────────────────────────────────────────────

    private void handleConnect(Socket clientSock, InputStream rawIn, OutputStream rawOut,
                                String target) throws Exception {
        // Extract hostname (strip port)
        String host = target.contains(":") ? target.substring(0, target.lastIndexOf(':')) : target;

        // Tell the browser the tunnel is ready
        rawOut.write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        rawOut.flush();

        // Wrap the client connection in SSL using a per-host cert signed by our CA
        SSLContext serverCtx = ca.serverContext(host);
        SSLSocket  sslSock   = (SSLSocket) serverCtx.getSocketFactory()
                .createSocket(clientSock, clientSock.getInetAddress().getHostAddress(),
                              clientSock.getPort(), true);
        sslSock.setUseClientMode(false);
        sslSock.setSoTimeout(30_000);

        try (sslSock) {
            InputStream  sslIn  = sslSock.getInputStream();
            OutputStream sslOut = sslSock.getOutputStream();

            // The browser now sends a decrypted HTTP request over the tunnel
            String innerLine = readLine(sslIn);
            if (innerLine == null || innerLine.isBlank()) return;
            Map<String, String> innerHeaders = readHeaders(sslIn);

            String[] p      = innerLine.split(" ", 3);
            if (p.length < 2) return;
            String method   = p[0].toUpperCase(Locale.ROOT);
            String path     = p[1];
            String fullUrl  = "https://" + host + path;

            // Inject the real host back so handleHttp can forward correctly
            innerHeaders.putIfAbsent("host", host);
            handleHttp(sslIn, sslOut,
                       method + " " + fullUrl + " HTTP/1.1",
                       innerHeaders, method, fullUrl, true);
        }
    }

    // ── HTTP (plain or decrypted HTTPS) ──────────────────────────────────────

    private void handleHttp(InputStream clientIn, OutputStream clientOut,
                             String requestLine, Map<String, String> headers,
                             String method, String target, boolean isTls) throws Exception {

        // Build absolute URL
        String urlStr;
        if (target.startsWith("http://") || target.startsWith("https://")) {
            urlStr = target;
        } else {
            String scheme = isTls ? "https" : "http";
            urlStr = scheme + "://" + headers.getOrDefault("host", "unknown") + target;
        }

        // Surface every intercepted request in the Logs tab so the user can confirm
        // the proxy is wired up and watch traffic flow in real time.  Truncated to
        // keep extremely long URLs from blowing up the log pane.
        String logUrl = urlStr.length() > 240 ? urlStr.substring(0, 240) + "…" : urlStr;
        logger.logToOutput("[Proxy] " + method + " " + logUrl);

        // Read request body if present
        byte[] reqBody = null;
        String clenHdr = headers.get("content-length");
        if (clenHdr != null) {
            try {
                int clen = Integer.parseInt(clenHdr.trim());
                if (clen > 0 && clen <= 10_000_000) reqBody = clientIn.readNBytes(clen);
            } catch (NumberFormatException ignored) {}
        }

        // Scan request headers for secrets (Authorization, Ocp-Apim-Subscription-Key, etc.)
        if (!headers.isEmpty()) {
            StringBuilder hdrBlob = new StringBuilder();
            headers.forEach((k, v) -> hdrBlob.append(k).append(": ").append(v).append("\n"));
            final String blob    = hdrBlob.toString();
            final String fUrl    = urlStr;
            pool.submit(() -> scanAsync(blob, "text/plain", fUrl + " [REQ-HEADERS]", fUrl));
        }

        // Scan request body (POST credentials, JSON payloads)
        if (reqBody != null && reqBody.length > 0) {
            String reqCt  = headers.getOrDefault("content-type", "text/plain").split(";")[0].trim();
            String reqStr = new String(reqBody, StandardCharsets.UTF_8);
            final String fUrl = urlStr;
            pool.submit(() -> scanAsync(reqStr, reqCt, fUrl + " [REQ-BODY]", fUrl));
        }

        // Forward request to real server
        URL    url  = new URL(urlStr);
        String host = url.getHost();
        int    port = url.getPort() > 0 ? url.getPort() : (isTls ? 443 : 80);
        String path = url.getFile().isEmpty() ? "/" : url.getFile();

        try (Socket server = isTls
                ? TRUST_ALL_CTX.getSocketFactory().createSocket(host, port)
                : new Socket()) {
            if (!isTls) {
                server.setSoTimeout(30_000);
                server.connect(new InetSocketAddress(host, port), 15_000);
            } else {
                server.setSoTimeout(30_000);
            }
            OutputStream serverOut = server.getOutputStream();
            InputStream  serverIn  = server.getInputStream();

            // Write the forwarded request
            StringBuilder fwdReq = new StringBuilder();
            fwdReq.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
            headers.forEach((k, v) -> {
                if (!k.equalsIgnoreCase("proxy-connection") &&
                    !k.equalsIgnoreCase("proxy-authorization")) {
                    fwdReq.append(k).append(": ").append(v).append("\r\n");
                }
            });
            fwdReq.append("connection: close\r\n\r\n");
            serverOut.write(fwdReq.toString().getBytes(StandardCharsets.US_ASCII));
            if (reqBody != null && reqBody.length > 0) serverOut.write(reqBody);
            serverOut.flush();

            // Read response status + headers from server
            String              statusLine   = readLine(serverIn);
            if (statusLine == null) return;
            Map<String, String> respHeaders  = readHeaders(serverIn);

            // Read response body
            String  transferEnc = respHeaders.getOrDefault("transfer-encoding", "");
            String  respClenHdr = respHeaders.get("content-length");
            byte[]  body;
            if ("chunked".equalsIgnoreCase(transferEnc.trim())) {
                body = readChunked(serverIn);
            } else if (respClenHdr != null) {
                int clen = Integer.parseInt(respClenHdr.trim());
                body = clen > 0 ? serverIn.readNBytes(clen) : new byte[0];
            } else {
                body = serverIn.readAllBytes();
            }

            // Relay response to browser
            StringBuilder respFwd = new StringBuilder();
            respFwd.append(statusLine).append("\r\n");
            respHeaders.forEach((k, v) -> {
                if (!k.equalsIgnoreCase("transfer-encoding"))  // we re-emit as content-length
                    respFwd.append(k).append(": ").append(v).append("\r\n");
            });
            respFwd.append("content-length: ").append(body.length).append("\r\n\r\n");
            clientOut.write(respFwd.toString().getBytes(StandardCharsets.US_ASCII));
            clientOut.write(body);
            clientOut.flush();

            // Scan response body asynchronously
            String respCt = respHeaders.getOrDefault("content-type", "").split(";")[0].trim();
            if (body.length > 0 && isTextContent(respCt)) {
                String bodyStr = new String(body, StandardCharsets.UTF_8);
                final String fUrl = urlStr;
                // Stash full request+response in the CaptureStore for the Details side-panel
                if (captureStore != null) {
                    StringBuilder reqBlob  = new StringBuilder();
                    headers.forEach((k, v) -> reqBlob.append(k).append(": ").append(v).append('\n'));
                    StringBuilder respBlob = new StringBuilder();
                    respHeaders.forEach((k, v) -> respBlob.append(k).append(": ").append(v).append('\n'));
                    String reqBodyStr = reqBody == null ? null : new String(reqBody, StandardCharsets.UTF_8);
                    int statusCode = 0;
                    try {
                        String[] slParts = statusLine.split(" ", 3);
                        if (slParts.length >= 2) statusCode = Integer.parseInt(slParts[1]);
                    } catch (NumberFormatException ignored) {}
                    captureStore.merge(fUrl, reqBlob.toString(), reqBodyStr,
                                       bodyStr, respCt, statusCode, statusLine,
                                       respBlob.toString(), method);
                }
                pool.submit(() -> scanAsync(bodyStr, respCt, fUrl, fUrl));
            }
        }
    }

    // ── Scanning ──────────────────────────────────────────────────────────────

    private void scanAsync(String text, String contentType, String url, String target) {
        try {
            List<SecretFinding> findings = scanner.scanText(text, contentType, url);
            if (!findings.isEmpty()) onFindings.accept(findings, target);
        } catch (Exception e) {
            logger.logToError("[Proxy] Scan error for " + url + ": " + e.getMessage());
        }
    }

    // ── I/O helpers ───────────────────────────────────────────────────────────

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') return sb.toString().stripTrailing();
            if (c != '\r') sb.append((char) c);
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    private static Map<String, String> readHeaders(InputStream in) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        String line;
        while ((line = readLine(in)) != null && !line.isBlank()) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT),
                            line.substring(colon + 1).trim());
            }
        }
        return headers;
    }

    private static byte[] readChunked(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) break;
            int size;
            try { size = Integer.parseInt(sizeLine.trim().split(";")[0], 16); }
            catch (NumberFormatException e) { break; }
            if (size == 0) break;
            byte[] chunk = in.readNBytes(size);
            baos.write(chunk);
            readLine(in); // trailing CRLF after each chunk
        }
        return baos.toByteArray();
    }

    private static boolean isTextContent(String ct) {
        String l = ct.toLowerCase(Locale.ROOT);
        return l.contains("javascript") || l.contains("json") || l.contains("html")
            || l.contains("xml") || l.contains("text/") || l.contains("form-urlencoded");
    }
}
