// PeerSig for Android. The native half is crates/android, built by the
// app's `cargoBuild` task; the window is the desktop app's (crates/app/ui).
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // The Android half of rustls-platform-verifier: the native code
        // checks the server's certificate with Android's trust store.
        maven {
            url = uri("https://github.com/rustls/rustls-platform-verifier/raw/maven-archive/android-release-support/maven/")
            content { includeGroup("org.rustls") }
        }
    }
}

rootProject.name = "PeerSig"
include(":app")
