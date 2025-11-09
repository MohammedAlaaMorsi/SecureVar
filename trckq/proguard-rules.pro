# TrckQ Library - ProGuard Rules
# Obfuscates internal implementation while exposing public API

# ===========================
# Public API - Keep for consumers
# ===========================

# TrckqManager singleton
-keep public class io.mohammedalaamorsi.trckq.TrckqManager {
    public *;
}

# Configuration classes
-keep public class io.mohammedalaamorsi.trckq.TrckqConfig {
    *;
}
-keep public class io.mohammedalaamorsi.trckq.TrckqAction** {
    *;
}

# Public interfaces
-keep public interface io.mohammedalaamorsi.trckq.SecretProvider {
    *;
}
-keep public interface io.mohammedalaamorsi.trckq.WriteKeyVerifier {
    *;
}

# WriteKey data class - used by consumers
-keep public class io.mohammedalaamorsi.trckq.WriteKey {
    public *;
    public ** component*();
}
-keepclassmembers class io.mohammedalaamorsi.trckq.WriteKey {
    public <init>(...);
}

# SecureVarDelegate - core library class
-keep public class io.mohammedalaamorsi.trckq.SecureVarDelegate {
    public *;
    public <init>(...);
}

# Keep getValue/setValue for Kotlin property delegation
-keepclassmembers class io.mohammedalaamorsi.trckq.SecureVarDelegate {
    public ** getValue(...);
    public void setValue(...);
    public void authorizedWrite(...);
}

# Public helper functions
-keep public class io.mohammedalaamorsi.trckq.TrckqKt {
    public *;
}
-keep public class io.mohammedalaamorsi.trckq.SecureVarWriterKt {
    public *;
}

# ===========================
# Internal - Obfuscate aggressively
# ===========================

# Obfuscate all private/internal crypto methods
-keepclassmembers class io.mohammedalaamorsi.trckq.SecureVarDelegate {
    private <methods>;
    private <fields>;
}

# Obfuscate sealed state classes but preserve structure
-keep,allowobfuscation class io.mohammedalaamorsi.trckq.SealedState
-keep,allowobfuscation class io.mohammedalaamorsi.trckq.SealedState$*

# Keep companion objects but obfuscate internals
-keepclassmembers class io.mohammedalaamorsi.trckq.WriteKey$Companion {
    public <methods>;
}

# ===========================
# Kotlin & Reflection
# ===========================

-keepattributes Signature,InnerClasses,EnclosingMethod,*Annotation*

# Kotlin metadata for reflection
-keep class kotlin.Metadata { *; }

# Keep property references
-keepclassmembers class * {
    ** get*();
    void set*(***);
}

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# ===========================
# Security & Crypto
# ===========================

# Preserve crypto implementations
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-keepclassmembers class * {
    javax.crypto.Cipher *;
    javax.crypto.Mac *;
    java.security.MessageDigest *;
}

# Keep Android Security library
-keep class androidx.security.crypto.** { *; }

# ===========================
# Optimization
# ===========================

-optimizationpasses 5
-allowaccessmodification
-dontusemixedcaseclassnames

# Keep source file and line numbers for stack traces
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
