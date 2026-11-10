package com.secretsifter;

/**
 * Simple logger interface — replaces burp.api.montoya.logging.Logging
 * so PlaywrightCrawler and SecretScanner can run outside Burp.
 */
public interface AppLogger {
    void logToOutput(String message);
    void logToError(String message);
}
