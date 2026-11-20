// The PeerSig app for Android: Kotlin for the VPN service, the
// notification and the window; the native library (crates/android) for
// the capture and the reports; the desktop app's window (crates/app/ui).

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val repo: File = rootDir.parentFile

// The version is the workspace's (Cargo.toml), like every PeerSig part.
val peersigVersion: String = Regex("""(?m)^version = "([^"]+)"""")
    .find(repo.resolve("Cargo.toml").readText())!!.groupValues[1]
val versionNumber: Int = peersigVersion.split(".").map { it.toInt() }.let { (a, b, c) -> a * 10000 + b * 100 + c }

val abis: List<String> = (findProperty("peersig.abis") as String).split(",").map { it.trim() }.filter { it.isNotEmpty() }
val rustLibs = layout.buildDirectory.dir("rustJniLibs")
val uiAssets = layout.buildDirectory.dir("generated/uiAssets")

android {
    namespace = "be.uclouvain.peersig"
    compileSdk = 35
    ndkVersion = "27.3.13750724"

    defaultConfig {
        applicationId = "be.uclouvain.peersig"
        // ConnectivityManager.getConnectionOwnerUid: Android 10.
        minSdk = 29
        targetSdk = 35
        versionCode = versionNumber
        versionName = peersigVersion
        ndk { abiFilters += abis }
    }

    signingConfigs {
        // A release key, when given (docs/android.md): -Ppeersig.keystore=...
        val ks = findProperty("peersig.keystore") as String?
        if (ks != null) {
            create("release") {
                storeFile = file(ks)
                storePassword = findProperty("peersig.keystorePassword") as String?
                keyAlias = findProperty("peersig.keyAlias") as String?
                keyPassword = findProperty("peersig.keyPassword") as String?
            }
        }
    }

    buildTypes {
        release {
            // The native side calls Kotlin methods by name: no shrinking.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets["main"].jniLibs.srcDir(rustLibs)
    sourceSets["main"].assets.srcDir(uiAssets)

    packaging {
        jniLibs.useLegacyPackaging = false
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Must match rustls-platform-verifier-android in Cargo.lock.
    implementation("org.rustls:rustls-platform-verifier:" + rustlsAndroidVersion())
}

/** The version of the verifier's Android half that Cargo.lock pins. */
fun rustlsAndroidVersion(): String {
    val lines = repo.resolve("Cargo.lock").readLines()
    val i = lines.indexOfFirst { it.trim() == "name = \"rustls-platform-verifier-android\"" }
    require(i >= 0) { "rustls-platform-verifier-android is not in Cargo.lock" }
    return Regex(""""([^"]+)"""").find(lines[i + 1])!!.groupValues[1]
}

// The native library, in release (forwarding every packet is too slow
// otherwise), for each ABI: cargo-ndk (cargo install cargo-ndk).
val cargoBuild by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds crates/android for " + abis.joinToString()
    workingDir = repo
    environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
    val args = mutableListOf("cargo", "ndk", "-P", "29", "-o", rustLibs.get().asFile.absolutePath)
    abis.forEach { args += listOf("-t", it) }
    args += listOf("build", "--locked", "--release", "-p", "peersig-android")
    commandLine(args)
    inputs.files(fileTree(repo.resolve("crates")) { include("**/*.rs", "**/Cargo.toml", "**/*.toml") }, repo.resolve("Cargo.lock"))
    outputs.dir(rustLibs)
}

// The desktop app's window, with the shim that stands in for Tauri
// (src/main/ui/android.js) and a content security policy.
val copyUi by tasks.registering(Sync::class) {
    from(repo.resolve("crates/app/ui")) {
        into("ui")
        filesMatching("index.html") {
            filter { line ->
                line.replace(
                    "<meta charset=\"utf-8\">",
                    "<meta charset=\"utf-8\">\n  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'\">",
                ).replace("<script src=\"app.js\"></script>", "<script src=\"android.js\"></script>\n  <script src=\"app.js\"></script>")
            }
        }
    }
    from("src/main/ui") { into("ui") }
    into(uiAssets)
}

tasks.named("preBuild") { dependsOn(cargoBuild, copyUi) }
