# TileOps release shrinking rules.

# JSch instantiates ciphers, KEX, signatures etc. by class name from its config table.
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**
# Optional JSch integrations we don't ship.
-dontwarn org.apache.logging.log4j.**
-dontwarn org.slf4j.**
-dontwarn com.sun.jna.**
-dontwarn org.newsclub.net.unix.**
-dontwarn org.ietf.jgss.**

# BouncyCastle: used by JSch's bc.* classes (Ed25519/X25519 on Android); keep the lightweight crypto API.
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.math.ec.rfc7748.** { *; }
-keep class org.bouncycastle.math.ec.rfc8032.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# Stack traces in crash reports stay readable (mapping file is kept with the build).
-keepattributes SourceFile,LineNumberTable

# ML Kit / Firebase components are created reflectively (ComponentDiscovery) from manifest metadata:
# keep the registrars' no-arg constructors or barcode scanning fails at runtime in release builds.
-keep class * implements com.google.firebase.components.ComponentRegistrar { <init>(); }
-keep class com.google.mlkit.**.*Registrar { <init>(); }
