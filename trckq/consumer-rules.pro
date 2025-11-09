# Consumer ProGuard rules for TrckQ Library
# These rules are automatically applied to apps that include this library

# Keep TrckQ public API
-keep public class io.mohammedalaamorsi.trckq.TrckqManager {
    public *;
}
-keep public class io.mohammedalaamorsi.trckq.TrckqConfig { *; }
-keep public class io.mohammedalaamorsi.trckq.TrckqAction** { *; }
-keep public interface io.mohammedalaamorsi.trckq.SecretProvider { *; }
-keep public interface io.mohammedalaamorsi.trckq.WriteKeyVerifier { *; }

# Keep WriteKey for API usage
-keep public class io.mohammedalaamorsi.trckq.WriteKey {
    public *;
}

# Keep SecureVarDelegate
-keep public class io.mohammedalaamorsi.trckq.SecureVarDelegate {
    public *;
    public <init>(...);
}

# Keep Kotlin property delegation methods
-keepclassmembers class io.mohammedalaamorsi.trckq.SecureVarDelegate {
    public ** getValue(...);
    public void setValue(...);
    public void authorizedWrite(...);
}

# Keep helper functions
-keep public class io.mohammedalaamorsi.trckq.TrckqKt { public *; }
-keep public class io.mohammedalaamorsi.trckq.SecureVarWriterKt { public *; }

# Preserve crypto classes needed by library
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-keep class androidx.security.crypto.** { *; }
