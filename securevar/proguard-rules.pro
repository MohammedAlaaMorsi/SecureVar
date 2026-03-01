# SecureVar Library - ProGuard Rules
# Obfuscates internal implementation while exposing public API

# ===========================
# Public API - Keep for consumers
# ===========================

# SecureVarManager singleton
-keep public class io.mohammedalaamorsi.securevar.SecureVarManager {
    public *;
}

# Configuration classes
-keep public class io.mohammedalaamorsi.securevar.SecureVarConfig {
    *;
}
-keep public class io.mohammedalaamorsi.securevar.SecureVarAction** {
    *;
}

# Public interfaces
-keep public interface io.mohammedalaamorsi.securevar.SecretProvider {
    *;
}
-keep public interface io.mohammedalaamorsi.securevar.WriteKeyVerifier {
    *;
}

# WriteKey data class - used by consumers
-keep public class io.mohammedalaamorsi.securevar.WriteKey {
    public *;
    public ** component*();
}
-keepclassmembers class io.mohammedalaamorsi.securevar.WriteKey {
    public <init>(...);
}

# SecureVarDelegate - core library class
-keep public class io.mohammedalaamorsi.securevar.SecureVarDelegate {
    public *;
    public <init>(...);
}

# Keep getValue/setValue for Kotlin property delegation
-keepclassmembers class io.mohammedalaamorsi.securevar.SecureVarDelegate {
    public ** getValue(...);
    public void setValue(...);
    public void authorizedWrite(...);
}

# Public helper functions
-keep public class io.mohammedalaamorsi.securevar.SecureVarKt {
    public *;
}
-keep public class io.mohammedalaamorsi.securevar.SecureVarWriterKt {
    public *;
}

# ===========================
# Internal - Obfuscate aggressively
# ===========================

# Obfuscate all private/internal crypto methods
-keepclassmembers class io.mohammedalaamorsi.securevar.SecureVarDelegate {
    private <methods>;
    private <fields>;
}

# Obfuscate sealed state classes but preserve structure
-keep,allowobfuscation class io.mohammedalaamorsi.securevar.SealedState
-keep,allowobfuscation class io.mohammedalaamorsi.securevar.SealedState$*

# Keep companion objects but obfuscate internals
-keepclassmembers class io.mohammedalaamorsi.securevar.WriteKey$Companion {
    public <methods>;
}

# ===========================
# Kotlin & Reflection
# ===========================

-keepattributes Signature,InnerClasses,EnclosingMethod,*Annotation*

# Kotlin metadata for reflection
-keep class kotlin.Metadata { *; }

# Keep property references - CRITICAL for SecureVarDelegate reflection
-keepclassmembers class * {
    ** get*();
    void set*(***);
    boolean is*();
}

# Keep all property descriptors used by Kotlin reflection
-keep class kotlin.reflect.jvm.internal.** { *; }
-keep class kotlin.reflect.** { *; }

# Preserve property names for classes using SecureVarDelegate
-keepclassmembers class * {
    @kotlin.jvm.JvmField io.mohammedalaamorsi.securevar.SecureVarDelegate *;
}

# Keep all methods that might be accessed via reflection by SecureVarDelegate
-keepclassmembers class * {
    *** *$delegate;
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
