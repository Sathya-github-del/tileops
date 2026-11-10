import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "dev.tileops.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.tileops.app"
        minSdk = 33  // Android 13+
        targetSdk = 37
        versionCode = 4
        versionName = "0.4.0"
    }

    // Release/upload key lives in ../secrets (never in git). Without it, release builds are unsigned.
    val uploadProps = rootProject.file("../secrets/upload-keystore.properties")
    signingConfigs {
        if (uploadProps.exists()) {
            val p = Properties().apply { uploadProps.inputStream().use { load(it) } }
            create("release") {
                storeFile = rootProject.file("../secrets/" + p.getProperty("storeFile"))
                storePassword = p.getProperty("storePassword")
                keyAlias = p.getProperty("keyAlias")
                keyPassword = p.getProperty("keyPassword")
            }
        }
        getByName("debug") {
            // project-local debug keystore if present (android/build.sh creates it); otherwise AGP's default
            val local = rootProject.file("debug.keystore")
            if (local.exists()) {
                storeFile = local
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
    }

    buildTypes {
        getByName("debug") { signingConfig = signingConfigs.getByName("debug") }
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (uploadProps.exists()) signingConfig = signingConfigs.getByName("release")
            // -PreleaseTest: same release build, installable next to the real app for device smoke tests
            if (project.hasProperty("releaseTest")) applicationIdSuffix = ".releasetest"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures { compose = true }

    testOptions { unitTests.isReturnDefaultValues = true }

    // The server setup script template + read-only helper are shared with the Python companion,
    // so phone-only mode generates exactly the same setup as the companion.
    sourceSets.getByName("main").assets.directories.add("../../companion/assets")

    // F-Droid: no Google-signed dependency metadata blob in the APK/AAB signing block.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    packaging {
        resources.excludes += setOf("META-INF/versions/9/OSGI-INF/MANIFEST.MF", "META-INF/DEPENDENCIES")
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.navigation:navigation-compose:2.10.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.fragment:fragment-ktx:1.9.1")
    implementation("androidx.datastore:datastore-preferences:1.3.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.zxing:core:3.5.3") // QR decoding, Apache-2.0 (no Google Play services)
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.work:work-runtime-ktx:2.12.0")
    implementation("androidx.glance:glance-appwidget:1.2.0")
    // phone-only mode: SSH client (maintained JSch fork) + BouncyCastle for Ed25519/X25519 on Android
    implementation("com.github.mwiede:jsch:2.28.8")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}
