plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.13.1"
}

repositories {
    mavenCentral()
}

version = "1.0.0"
description = "Detects secrets, credentials, API tokens and PII exposed in live HTTP traffic."

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

zapAddOn {
    addOnName.set("OWASP SecretSifter")
    // Minimum ZAP version this add-on supports.
    zapVersion.set("2.16.0")

    manifest {
        author.set("Hemanth Gorijala / OWASP SecretSifter")
        url.set("https://owasp.org/projects/secretsifter")
        repo.set("https://github.com/secretsifter/zap-secretsifter")
        description.set(
            "Passive detection of secrets, credentials, API tokens and PII exposed in " +
                "live HTTP traffic — response bodies, JavaScript bundles, SSR state blobs, " +
                "and request headers. Runs the unified 437-rule OWASP SecretSifter engine " +
                "(158 format-anchored vendor tokens + 279 context rules), shared with the " +
                "SecretSifter Burp, desktop and browser editions."
        )
        // Passive scanning framework (bundled with ZAP by default since 2.16).
        dependencies {
            addOns {
                register("pscan")
            }
        }
    }
}

dependencies {
    // JSON body walker used by the detection engine — bundled into the add-on.
    implementation("com.google.code.gson:gson:2.10.1")
    // YAML rule-pack loader (builtin-anchored / builtin-context) — bundled into the add-on.
    implementation("org.yaml:snakeyaml:2.7")
}
