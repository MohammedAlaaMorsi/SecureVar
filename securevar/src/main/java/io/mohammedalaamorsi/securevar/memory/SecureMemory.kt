package io.mohammedalaamorsi.securevar.memory

import java.util.Arrays

/**
 * Utility for minimising plaintext exposure in memory.
 *
 * Java/Kotlin Strings are immutable and backed by a `byte[]` (Java 9+) or `char[]`.
 * Once a String is created the plaintext lives in the heap until garbage-collected.
 * This class provides **best-effort** wiping via reflection and secure-scope patterns.
 *
 * > **Limitation**: HotSpot / ART may keep copies (interned strings, JIT optimised registers).
 * > This reduces – but cannot eliminate – the exposure window.
 *
 * Usage:
 * ```kotlin
 * val plaintext = decryptSomething()
 * // … use plaintext …
 * SecureMemory.wipeString(plaintext) // zero out backing array
 *
 * // Or use a scope that auto-wipes:
 * SecureMemory.withSecureScope { scope ->
 *     val secret = scope.track(decryptSomething())
 *     // … use secret …
 * }   // backing arrays wiped on exit
 * ```
 */
object SecureMemory {

    // ── String wiping ───────────────────────────────────────────────────

    /**
     * Best-effort wipe of a String's backing array via reflection.
     * Returns `true` if the wipe succeeded, `false` if reflection was blocked.
     */
    fun wipeString(str: String?): Boolean {
        if (str == null || str.isEmpty()) return true
        return try {
            // Java 9+ compact strings use byte[]
            val valueField = String::class.java.getDeclaredField("value")
            valueField.isAccessible = true
            val backing = valueField.get(str)
            when (backing) {
                is ByteArray -> { Arrays.fill(backing, 0.toByte()); true }
                is CharArray -> { Arrays.fill(backing, '\u0000'); true }
                else -> false
            }
        } catch (_: Exception) {
            false
        }
    }

    // ── Array wiping ────────────────────────────────────────────────────

    /** Zero-fill a byte array. */
    fun wipeByteArray(arr: ByteArray?) {
        if (arr != null) Arrays.fill(arr, 0.toByte())
    }

    /** Zero-fill a char array. */
    fun wipeCharArray(arr: CharArray?) {
        if (arr != null) Arrays.fill(arr, '\u0000')
    }

    // ── Secure scope ────────────────────────────────────────────────────

    /**
     * Execute [block] inside a scope that tracks created Strings and
     * wipes them all on exit (including abnormal exit).
     */
    inline fun <R> withSecureScope(block: (SecureScope) -> R): R {
        val scope = SecureScope()
        return try {
            block(scope)
        } finally {
            scope.wipeAll()
        }
    }

    /**
     * A collector that holds references to temporary secrets.
     * Call [track] for every String whose backing array should be wiped on scope exit.
     */
    class SecureScope {
        private val tracked = mutableListOf<String>()
        private val trackedBytes = mutableListOf<ByteArray>()
        private val trackedChars = mutableListOf<CharArray>()

        /** Track a String for later wiping. Returns the same String for chaining. */
        fun track(str: String): String { tracked.add(str); return str }

        /** Track a byte array for later wiping. */
        fun track(arr: ByteArray): ByteArray { trackedBytes.add(arr); return arr }

        /** Track a char array for later wiping. */
        fun track(arr: CharArray): CharArray { trackedChars.add(arr); return arr }

        /** Wipe all tracked values. Called automatically on scope exit. */
        fun wipeAll() {
            tracked.forEach { wipeString(it) }
            tracked.clear()
            trackedBytes.forEach { wipeByteArray(it) }
            trackedBytes.clear()
            trackedChars.forEach { wipeCharArray(it) }
            trackedChars.clear()
        }
    }
}
