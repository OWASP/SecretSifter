package com.secretsifter;

import java.util.prefs.Preferences;

/**
 * Thin wrapper around Java's built-in {@link Preferences} API.
 * Provides the same getBoolean/setBoolean/getString/setString contract
 * that Montoya's Preferences interface offered — returning null when a
 * key has never been written, so ScanSettings.loadFromPrefs() can skip
 * unset keys rather than overwriting defaults.
 *
 * Persistence location:
 *   macOS  — ~/Library/Preferences/com.secretsifter.plist
 *   Windows — HKCU\Software\JavaSoft\Prefs\com\secretsifter
 *   Linux  — ~/.java/.userPrefs/com/secretsifter/
 */
public class AppPrefs {

    private final Preferences prefs = Preferences.userNodeForPackage(AppPrefs.class);

    // Booleans are stored as "true"/"false" strings so that a null return from
    // prefs.get(key, null) unambiguously means "key not set yet".

    public void setBoolean(String key, boolean val) {
        prefs.put(key, String.valueOf(val));
    }

    public Boolean getBoolean(String key) {
        String v = prefs.get(key, null);
        if (v == null) return null;
        return Boolean.parseBoolean(v);
    }

    public void setString(String key, String val) {
        if (val == null) prefs.remove(key);
        else             prefs.put(key, val);
    }

    public String getString(String key) {
        return prefs.get(key, null);
    }

    /** Force-flush pending writes to the backing store (Windows registry / plist). */
    public void flush() {
        try { prefs.flush(); } catch (Exception ignored) {}
    }
}
