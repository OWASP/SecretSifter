#!/bin/bash
# SecretSifter launcher — double-click this file on macOS to start SecretSifter.
# Finds Java 17+ automatically; falls back to instructing the user if none found.

DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$DIR/secretsifter-1.1.0.jar"
# Fall back to any secretsifter-*.jar if exact version not found
if [ ! -f "$JAR" ]; then
    JAR=$(ls "$DIR/secretsifter-"*.jar 2>/dev/null | sort -V | tail -1)
fi

if [ ! -f "$JAR" ]; then
    echo "ERROR: No secretsifter-*.jar found in $DIR"
    read -rp "Press Enter to close…"
    exit 1
fi

# ── Find a Java 17+ executable ─────────────────────────────────────────────
find_java() {
    local candidates=(
        "/opt/homebrew/opt/java/bin/java"
        "/opt/homebrew/opt/openjdk/bin/java"
        "/usr/local/opt/java/bin/java"
        "/usr/local/opt/openjdk/bin/java"
    )
    # Also check JAVA_HOME if set
    [ -n "$JAVA_HOME" ] && candidates=("$JAVA_HOME/bin/java" "${candidates[@]}")

    for exe in "${candidates[@]}"; do
        if [ -x "$exe" ]; then
            local ver
            ver=$("$exe" -version 2>&1 | awk -F '"' '/version/{print $2}' | cut -d. -f1)
            if [ "${ver:-0}" -ge 17 ] 2>/dev/null; then
                echo "$exe"
                return 0
            fi
        fi
    done

    # Last resort: whatever 'java' is on PATH
    local path_java
    path_java=$(command -v java 2>/dev/null)
    if [ -n "$path_java" ]; then
        local ver
        ver=$("$path_java" -version 2>&1 | awk -F '"' '/version/{print $2}' | cut -d. -f1)
        if [ "${ver:-0}" -ge 17 ] 2>/dev/null; then
            echo "$path_java"
            return 0
        fi
    fi

    return 1
}

JAVA_EXE=$(find_java)
if [ -z "$JAVA_EXE" ]; then
    echo ""
    echo "ERROR: Java 17 or later is required but was not found."
    echo ""
    echo "Install it with Homebrew:  brew install java"
    echo "Or download from:          https://adoptium.net"
    echo ""
    read -rp "Press Enter to close…"
    exit 1
fi

echo "Launching SecretSifter with $JAVA_EXE …"
ICON="$DIR/SecretSifter.app/Contents/Resources/SecretSifter.icns"
exec "$JAVA_EXE" \
    -Xdock:name="SecretSifter" \
    -Xdock:icon="$ICON" \
    -Dapple.awt.application.name="SecretSifter" \
    -jar "$JAR"
