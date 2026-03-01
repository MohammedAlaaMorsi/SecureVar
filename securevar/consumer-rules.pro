# Consumer ProGuard rules for SecureVar Library
# These rules are automatically applied to apps that include this library

# Keep SecureVar public API
-keep public class io.mohammedalaamorsi.securevar.SecureVarManager {
    public *;
}
-keep public class io.mohammedalaamorsi.securevar.SecureVarConfig { *; }
-keep public class io.mohammedalaamorsi.securevar.SecureVarAction** { *; }
-keep public interface io.mohammedalaamorsi.securevar.SecretProvider { *; }
-keep public interface io.mohammedalaamorsi.securevar.WriteKeyVerifier { *; }

# Keep WriteKey for API usage
-keep public class io.mohammedalaamorsi.securevar.WriteKey {
    public *;
}

# Keep SecureVarDelegate
-keep public class io.mohammedalaamorsi.securevar.SecureVarDelegate {
    public *;
    public <init>(...);
}

# Keep Kotlin property delegation methods
-keepclassmembers class io.mohammedalaamorsi.securevar.SecureVarDelegate {
    public ** getValue(...);
    public void setValue(...);
    public void authorizedWrite(...);
}

# Keep helper functions
-keep public class io.mohammedalaamorsi.securevar.SecureVarKt { public *; }
-keep public class io.mohammedalaamorsi.securevar.SecureVarWriterKt { public *; }

# Preserve crypto classes needed by library
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-keep class androidx.security.crypto.** { *; }
