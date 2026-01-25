package io.mohammedalaamorsi.trckq.risk

import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * comprehensive risk detection utility.
 * detects:
 * - Root access
 * - Hooking frameworks (Frida, Xposed)
 * - Emulator environment
 */
object RiskDetector {

    /**
     * Checks if the device is running in a high-risk environment.
     * @param context Application context for system checks
     * @return true if any risk is detected.
     */
    fun isHighRisk(context: android.content.Context): Boolean {
        return isRooted() || isHooked() || isEmulator() || isDebuggerAttached(context)
    }

    /**
     * Checks for root access indicators.
     */
    fun isRooted(): Boolean {
        return checkRootFiles() || checkSuExists() || checkRootBuildTags()
    }

    /**
     * Checks for hooking frameworks (Frida, Xposed).
     */
    fun isHooked(): Boolean {
        return checkFridaPorts() || checkFridaMaps() || checkXposedClasses()
    }

    /**
     * Checks if the app is running on an emulator.
     */
    fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk" == Build.PRODUCT)
    }

    /**
     * Checks if a debugger is attached.
     */
    fun isDebuggerAttached(context: android.content.Context): Boolean {
        return android.os.Debug.isDebuggerConnected() || 
               android.provider.Settings.Global.getInt(
                   context.contentResolver,
                   android.provider.Settings.Global.WAIT_FOR_DEBUGGER, 0
               ) != 0
    }

    // --- Internal Checks ---

    private fun checkRootFiles(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkSuExists(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val br = BufferedReader(java.io.InputStreamReader(process.inputStream))
            br.readLine() != null
        } catch (t: Throwable) {
            false
        } finally {
            process?.destroy()
        }
    }

    private fun checkRootBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkFridaPorts(): Boolean {
        // Default Frida server port
        return try {
            java.net.Socket("127.0.0.1", 27042).close()
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun checkFridaMaps(): Boolean {
        return try {
            val file = File("/proc/self/maps")
            if (!file.exists()) return false
            
            val reader = BufferedReader(FileReader(file))
            var line: String?
            var detected = false
            while (reader.readLine().also { line = it } != null) {
                if (line != null && (line!!.contains("frida-agent") || line!!.contains("gum-js-loop"))) {
                    detected = true
                    break
                }
            }
            reader.close()
            detected
        } catch (e: Exception) {
            false
        }
    }

    private fun checkXposedClasses(): Boolean {
        val suspicious = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers"
        )
        for (name in suspicious) {
            try {
                Class.forName(name)
                return true
            } catch (e: ClassNotFoundException) {
                // Ignore
            }
        }
        return false
    }
}
