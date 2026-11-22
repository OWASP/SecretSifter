package com.secretscanner;

/**
 * Minimal logging shim so the portable scanning core ({@link SecretScanner})
 * compiles without the Burp Montoya API.  Backed by {@code java.util.logging}
 * to keep the {@code com.secretscanner} core dependency-free (Gson only).
 *
 * The ZAP glue can supply an instance; a {@code null} logging reference is
 * tolerated by the scanner.
 */
public final class Logging {

    private static final java.util.logging.Logger LOG =
            java.util.logging.Logger.getLogger("SecretSifter");

    public void logToOutput(String message) {
        LOG.info(message);
    }

    public void logToError(String message) {
        LOG.warning(message);
    }
}