# ── SecretSifter ProGuard Rules ───────────────────────────────────────────────
# Goal: obfuscate com.secretsifter.* only.
#
# ProGuard processes ONLY the extracted com/secretsifter/ classes (Step 2b).
# The full fat JAR (minus com/secretsifter/) is passed as -libraryjars so
# ProGuard can resolve type references but never re-writes Playwright's code.
# This eliminates the root cause of the "Could not initialize class
# impl.Serialization" error seen when ProGuard processed the full fat JAR.

# ── Disable shrinking and optimisation ────────────────────────────────────────
# Shrinking: our extracted JAR has only 36 classes; removing any risks breaking
#            runtime reflective references inside Playwright or FlatLaf.
# Optimisation: can break Swing/AWT and reflection-heavy code.
-dontshrink
-dontoptimize

# ── Entry point: must stay by name (jpackage launcher hard-codes this) ─────────
-keep public class com.secretsifter.SecretSifterApp {
    public static void main(java.lang.String[]);
}

# ── Serialisation safety ───────────────────────────────────────────────────────
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ── Swing L&F (FlatLaf loads ComponentUI subclasses by name at runtime) ────────
-keep class * extends javax.swing.plaf.ComponentUI {
    public static javax.swing.plaf.ComponentUI createUI(javax.swing.JComponent);
}

# ── Enum constant names: the rule engine and validation layer match fixed
#    strings from YAML / JSON / user input against enum constants via
#    Enum.valueOf(...) (e.g. kind: anchored, severity, ScanTier, Validation state).
#    Obfuscating the constant names breaks valueOf — keep all enum members.
-keepclassmembers enum com.secretsifter.** {
    *;
}
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}


# ── Suppress warnings from library resolution ─────────────────────────────────
-dontwarn **

# ── Obfuscation mapping (keep this file — needed to decode stack traces) ───────
-printmapping build/proguard-mapping.txt
