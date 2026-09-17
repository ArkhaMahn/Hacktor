import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    java
    id("org.zaproxy.add-on") version "0.13.1"
}

group = "org.zaproxy.zap.extension"
version = "1.0.0"
description = "HTTP request tampering and fuzzing lab: 7800+ techniques across 40+ families for access-control bypass, auth/authz probing, HTTP smuggling, cache poisoning, injection probing, and OAuth 1.0a/2.0/OIDC tampering."

repositories { mavenCentral() }

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

zapAddOn {
    addOnName.set("Hacktor")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.17.0")
    manifest {
        author.set("ArkhaMahn")
        url.set("https://github.com/zaproxy/zap-extensions")
        bundle {
            baseName.set("org.zaproxy.zap.extension.hacktor.Messages")
            prefix.set("hacktor")
        }
    }
}
