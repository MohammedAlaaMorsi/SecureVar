package io.mohammedalaamorsi.securevar.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Multi-signal origin verification for SecureVar.
 *
 * Goes beyond simple stack-trace prefix checks to provide defense-in-depth
 * against call-site spoofing, code injection, and tampered APKs.
 *
 * Signals verified:
 * 1. Stack trace origin (allowed package prefixes)
 * 2. ClassLoader validation (expected class loader hierarchy)
 * 3. APK signature verification (certificate hash pinning)
 *
 * Usage:
 * ```kotlin
 * val verifier = OriginVerifier.Builder(context)
 *     .allowPackage("io.mohammedalaamorsi.myapp")
 *     .pinSignature("SHA-256:AB:CD:EF:...")
 *     .build()
 *
 * if (!verifier.verify()) {
 *     // Reject the call
 * }
 * ```
 */
class OriginVerifier private constructor(
    private val allowedPackages: List<String>,
    private val pinnedSignatureHashes: List<String>,
    private val appContext: Context?,
    private val expectedCallDepthRange: IntRange?,
    private val expectedCallerMethods: List<String>
) {

    /**
     * Verification result with detailed failure info.
     */
    data class VerificationResult(
        val allowed: Boolean,
        val failureReasons: List<String> = emptyList()
    )

    /**
     * Quick boolean check.
     */
    fun verify(): Boolean = verifyDetailed().allowed

    /**
     * Detailed verification with failure reasons.
     */
    fun verifyDetailed(): VerificationResult {
        val failures = mutableListOf<String>()

        // 1. Stack trace origin check
        if (!verifyStackTrace()) {
            failures.add("stack_trace:no_allowed_package_in_call_chain")
        }

        // 2. ClassLoader validation
        if (!verifyClassLoader()) {
            failures.add("classloader:unexpected_classloader_hierarchy")
        }

        // 3. APK signature verification (if context and pins provided)
        if (appContext != null && pinnedSignatureHashes.isNotEmpty()) {
            if (!verifyApkSignature(appContext)) {
                failures.add("signature:apk_signature_mismatch")
            }
        }

        // 4. Call chain depth validation
        if (!verifyCallDepth()) {
            failures.add("call_depth:outside_expected_range")
        }

        // 5. Expected caller method verification
        if (!verifyCallerMethods()) {
            failures.add("caller_method:expected_method_missing")
        }

        return VerificationResult(
            allowed = failures.isEmpty(),
            failureReasons = failures
        )
    }

    // ── Stack trace verification ────────────────────────────────────────

    private fun verifyStackTrace(): Boolean {
        if (allowedPackages.isEmpty()) return true

        val stackTrace = Throwable().stackTrace
        // Skip first few frames (OriginVerifier itself, SecureVarDelegate)
        val callerFrames = stackTrace.drop(2)
        return callerFrames.any { frame ->
            allowedPackages.any { prefix -> frame.className.startsWith(prefix) }
        }
    }

    // ── ClassLoader validation ──────────────────────────────────────────

    private fun verifyClassLoader(): Boolean {
        val stackTrace = Throwable().stackTrace
        val callerFrames = stackTrace.drop(2)

        for (frame in callerFrames) {
            if (allowedPackages.any { frame.className.startsWith(it) }) {
                // Found a caller in our allowed packages — verify its ClassLoader
                try {
                    val callerClass = Class.forName(frame.className, false, javaClass.classLoader)
                    val loader = callerClass.classLoader ?: continue

                    // The expected ClassLoader for Android app code is PathClassLoader
                    // Injected code (Frida, Xposed) often uses a custom DexClassLoader or InMemoryDexClassLoader
                    val loaderName = loader.javaClass.name
                    if (loaderName.contains("dalvik.system.PathClassLoader") ||
                        loaderName.contains("dalvik.system.DelegateLastClassLoader") ||
                        loaderName.contains("java.lang.BootClassLoader")) {
                        return true // Expected loader
                    }

                    // Suspicious class loader detected
                    return false
                } catch (_: ClassNotFoundException) {
                    // Could not load the class at all — suspicious
                    return false
                } catch (_: Exception) {
                    continue
                }
            }
        }

        // If no caller in allowed packages was found in stack, that's a stack trace failure,
        // not a classloader failure — allow through (stack trace check will catch it)
        return true
    }

    // ── APK signature verification ──────────────────────────────────────

    @Suppress("DEPRECATION")
    private fun verifyApkSignature(context: Context): Boolean {
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signingInfo = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                ).signingInfo
                if (signingInfo == null) {
                    null
                } else if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                ).signatures
            }

            if (signatures.isNullOrEmpty()) return false

            val currentHashes = signatures.map { sig ->
                val digest = MessageDigest.getInstance("SHA-256")
                val hash = digest.digest(sig.toByteArray())
                "SHA-256:" + hash.joinToString(":") { "%02X".format(it) }
            }

            // At least one pinned hash must match
            pinnedSignatureHashes.any { pinned ->
                currentHashes.any { current ->
                    current.equals(pinned, ignoreCase = true)
                }
            }
        } catch (_: Exception) {
            false
        }
    }

    // ── Call depth validation ────────────────────────────────────────────

    private fun verifyCallDepth(): Boolean {
        val range = expectedCallDepthRange ?: return true // Not configured
        val depth = Throwable().stackTrace.size
        return depth in range
    }

    // ── Caller method verification ──────────────────────────────────────

    private fun verifyCallerMethods(): Boolean {
        if (expectedCallerMethods.isEmpty()) return true
        val stackTrace = Throwable().stackTrace
        return expectedCallerMethods.all { expectedMethod ->
            stackTrace.any { frame -> frame.methodName == expectedMethod }
        }
    }

    // ── Builder ─────────────────────────────────────────────────────────

    class Builder(private val context: Context? = null) {
        private val packages = mutableListOf<String>()
        private val signatures = mutableListOf<String>()
        private var callDepthRange: IntRange? = null
        private val callerMethods = mutableListOf<String>()

        /** Add an allowed calling package prefix. */
        fun allowPackage(prefix: String) = apply { packages.add(prefix) }

        /** Add multiple allowed package prefixes. */
        fun allowPackages(prefixes: List<String>) = apply { packages.addAll(prefixes) }

        /** Pin an APK signing certificate hash (format: "SHA-256:AB:CD:..."). */
        fun pinSignature(hash: String) = apply { signatures.add(hash) }

        /** Set expected call stack depth range. Spoofed stacks often have abnormal depth. */
        fun expectCallDepth(range: IntRange) = apply { callDepthRange = range }

        /** Add an expected method name that must appear in the call chain. */
        fun expectCallerMethod(methodName: String) = apply { callerMethods.add(methodName) }

        fun build(): OriginVerifier {
            return OriginVerifier(
                allowedPackages = packages.toList(),
                pinnedSignatureHashes = signatures.toList(),
                appContext = context,
                expectedCallDepthRange = callDepthRange,
                expectedCallerMethods = callerMethods.toList()
            )
        }
    }

    companion object {
        /**
         * Create a simple verifier with just allowed packages (no context needed).
         */
        fun withPackages(vararg packages: String): OriginVerifier {
            return Builder().allowPackages(packages.toList()).build()
        }
    }
}
