---
'@openkey/sdk-capacitor': patch
---

Fix the Android build in host apps that already have the Kotlin Gradle plugin on their buildscript classpath: the plugin now uses the host's `kotlin_version` (default 2.1.0 when the host sets none) instead of requesting `org.jetbrains.kotlin.android` 2.1.0 itself, which failed with "plugin is already on the classpath with an unknown version".
