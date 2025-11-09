# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
-renamesourcefileattribute SourceFile

# ===========================
# TrckQ Security Library Rules
# ===========================

# Keep public API of TrckQ library
-keep public class io.mohammedalaamorsi.trckq.TrckqManager {
    public *;
}
-keep public class io.mohammedalaamorsi.trckq.TrckqConfig {
    *;
}
-keep public class io.mohammedalaamorsi.trckq.TrckqAction** {
    *;
}
-keep public interface io.mohammedalaamorsi.trckq.SecretProvider {
    *;
}
-keep public interface io.mohammedalaamorsi.trckq.WriteKeyVerifier {
    *;
}

# Keep WriteKey class (used for authorization)
-keep public class io.mohammedalaamorsi.trckq.WriteKey {
    public *;
}

# Keep SecureVarDelegate for reflection/property delegation
-keep public class io.mohammedalaamorsi.trckq.SecureVarDelegate {
    public *;
    private <fields>;
}

# Keep helper functions
-keep public class io.mohammedalaamorsi.trckq.TrckqKt {
    public *;
}

# Obfuscate internal crypto implementation but preserve signatures
-keepclassmembers class io.mohammedalaamorsi.trckq.SecureVarDelegate {
    private *** encrypt(...);
    private *** decrypt(...);
    private *** createMac(...);
}

# Keep Application class
-keep public class io.mohammedalaamorsi.trckqapp.TrckQApplication {
    public *;
}

# Keep SessionManager and its properties (uses SecureVarDelegate)
-keep class io.mohammedalaamorsi.trckqapp.domain.manager.SessionManager {
    public *;
    private io.mohammedalaamorsi.trckq.SecureVarDelegate *;
}

# Keep all property getters/setters for classes using SecureVarDelegate
-keepclassmembers class io.mohammedalaamorsi.trckqapp.domain.manager.** {
    *** getUsername();
    void setUsername(***);
    *** getUserId();
    void setUserId(***);
    *** isPremiumUser();
    void setPremiumUser(***);
    boolean is*();
    *** get*();
    void set*(***);
}

# ===========================
# Kotlin Rules
# ===========================

# Keep Kotlin metadata for reflection
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}
-keepclassmembers class kotlin.coroutines.SafeContinuation {
    volatile <fields>;
}

# Kotlin serialization
-keepattributes InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# Keep sealed classes
-keep,allowobfuscation,allowshrinking class io.mohammedalaamorsi.trckq.SealedState
-keep,allowobfuscation,allowshrinking class io.mohammedalaamorsi.trckq.SealedState$*

# ===========================
# Android & Jetpack Compose
# ===========================

# Jetpack Compose
-dontwarn androidx.compose.**
-keep class androidx.compose.** { *; }
-keepclassmembers class androidx.compose.** { *; }

# Keep ViewModel
-keep class * extends androidx.lifecycle.ViewModel {
    <init>();
}
-keep class * extends androidx.lifecycle.AndroidViewModel {
    <init>(android.app.Application);
}

# Keep Parcelable
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# ===========================
# Security & Crypto
# ===========================

# Keep Android Security Crypto library
-keep class androidx.security.crypto.** { *; }
-keep interface androidx.security.crypto.** { *; }

# Keep Java crypto classes (needed for HMAC/AES)
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-dontwarn javax.crypto.**
-dontwarn java.security.**

# Keep SecureRandom
-keep class java.security.SecureRandom { *; }

# Suppress warnings for missing annotations
-dontwarn javax.annotation.**
-dontwarn javax.annotation.concurrent.**

# ===========================
# Testing & Debug
# ===========================

# Keep test classes (won't be in release anyway)
-dontwarn org.junit.**
-dontwarn junit.**

# Remove logging in release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# But keep error/warning logs
-keep class android.util.Log {
    public static *** e(...);
    public static *** w(...);
}

# ===========================
# Optimization
# ===========================

# Aggressive optimization
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Remove debug info but keep line numbers for crash reports
-keepattributes SourceFile,LineNumberTable

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}
