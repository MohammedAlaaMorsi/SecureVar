package io.mohammedalaamorsi.securevar.risk

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.InputStreamReader

/**
 * Comprehensive risk detection utility for SecureVar.
 *
 * Detects:
 * - Root access (SU binaries, Magisk, KernelSU, build tags, system properties)
 * - Hooking frameworks (Frida gadget, Xposed, LSPosed, Substrate)
 * - Emulator environments
 * - Debugger attachment
 * - Debuggable build flags
 * - Suspicious installed packages
 */
object RiskDetector {

    /**
     * Structured risk report with individual detection results.
     */
    data class RiskReport(
        val rooted: Boolean,
        val hooked: Boolean,
        val emulator: Boolean,
        val debuggerAttached: Boolean,
        val debuggableBuild: Boolean,
        val suspiciousPackages: List<String>,
        val details: List<String>
    ) {
        /** True if any risk signal is detected. */
        val highRisk: Boolean
            get() = rooted || hooked || emulator || debuggerAttached || debuggableBuild || suspiciousPackages.isNotEmpty()
    }

    /**
     * Quick boolean check: is the device in a high-risk environment?
     */
    fun isHighRisk(context: Context): Boolean {
        return getDetailedRiskReport(context).highRisk
    }

    /**
     * Returns a structured [RiskReport] with all detected risk signals.
     */
    fun getDetailedRiskReport(context: Context): RiskReport {
        val details = mutableListOf<String>()

        val rooted = isRooted(details)
        val hooked = isHooked(details)
        val emulator = isEmulator(details)
        val debugger = isDebuggerAttached(context, details)
        val debuggable = isDebuggableBuild(context, details)
        val packages = detectSuspiciousPackages(context, details)

        return RiskReport(
            rooted = rooted,
            hooked = hooked,
            emulator = emulator,
            debuggerAttached = debugger,
            debuggableBuild = debuggable,
            suspiciousPackages = packages,
            details = details
        )
    }

    // ── Root detection ──────────────────────────────────────────────────

    fun isRooted(): Boolean = isRooted(null)

    private fun isRooted(details: MutableList<String>?): Boolean {
        var detected = false
        if (checkRootFiles()) { details?.add("root:su_binaries_found"); detected = true }
        if (checkSuExists()) { details?.add("root:su_executable"); detected = true }
        if (checkRootBuildTags()) { details?.add("root:test_keys"); detected = true }
        if (checkMagisk()) { details?.add("root:magisk_detected"); detected = true }
        if (checkKernelSU()) { details?.add("root:kernelsu_detected"); detected = true }
        if (checkRootProperties()) { details?.add("root:suspicious_properties"); detected = true }
        if (checkMountNamespaces()) { details?.add("root:mount_namespace_anomaly"); detected = true }
        if (checkSELinuxPermissive()) { details?.add("root:selinux_permissive"); detected = true }
        if (checkZygiskDenyList()) { details?.add("root:zygisk_denylist_artifacts"); detected = true }
        if (checkProcAccessibility()) { details?.add("root:proc_access_restricted"); detected = true }
        if (checkNativeProperties()) { details?.add("root:native_prop_suspicious"); detected = true }
        return detected
    }

    // ── Hook detection ──────────────────────────────────────────────────

    fun isHooked(): Boolean = isHooked(null)

    private fun isHooked(details: MutableList<String>?): Boolean {
        var detected = false
        if (checkFridaPorts()) { details?.add("hook:frida_port_open"); detected = true }
        if (checkFridaMaps()) { details?.add("hook:frida_agent_in_maps"); detected = true }
        if (checkFridaGadget()) { details?.add("hook:frida_gadget_loaded"); detected = true }
        if (checkXposedClasses()) { details?.add("hook:xposed_classes_loaded"); detected = true }
        if (checkSubstrate()) { details?.add("hook:substrate_detected"); detected = true }
        if (checkNativeHookLibraries()) { details?.add("hook:native_hook_lib_in_maps"); detected = true }
        if (checkFridaThreadNames()) { details?.add("hook:frida_thread_detected"); detected = true }
        if (checkFridaPortRange()) { details?.add("hook:frida_nondefault_port"); detected = true }
        if (checkSuspiciousFileDescriptors()) { details?.add("hook:suspicious_fd"); detected = true }
        if (checkProcessNameIntegrity()) { details?.add("hook:process_name_tampered"); detected = true }
        return detected
    }

    // ── Emulator detection ──────────────────────────────────────────────

    fun isEmulator(): Boolean = isEmulator(null)

    private fun isEmulator(details: MutableList<String>?): Boolean {
        val indicators = mutableListOf<String>()

        if (Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.startsWith("unknown"))
            indicators.add("fingerprint")
        if (Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for x86"))
            indicators.add("model")
        if (Build.MANUFACTURER.contains("Genymotion"))
            indicators.add("genymotion")
        if (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
            indicators.add("generic_brand_device")
        if ("google_sdk" == Build.PRODUCT || "sdk_gphone" in Build.PRODUCT)
            indicators.add("product")
        if (Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu"))
            indicators.add("hardware")
        // Check for QEMU pipes
        if (File("/dev/qemu_pipe").exists() || File("/dev/socket/qemud").exists())
            indicators.add("qemu_pipe")

        if (indicators.isNotEmpty()) {
            details?.add("emulator:${indicators.joinToString(",")}")
        }
        return indicators.isNotEmpty()
    }

    // ── Debugger detection ──────────────────────────────────────────────

    fun isDebuggerAttached(context: Context): Boolean = isDebuggerAttached(context, null)

    private fun isDebuggerAttached(context: Context, details: MutableList<String>?): Boolean {
        val connected = android.os.Debug.isDebuggerConnected()
        val waitFlag = try {
            android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.WAIT_FOR_DEBUGGER, 0
            ) != 0
        } catch (_: Exception) { false }

        // Check for TracerPid in /proc/self/status (ptrace detection)
        val traced = checkTracerPid()

        val detected = connected || waitFlag || traced
        if (detected) {
            val reasons = mutableListOf<String>()
            if (connected) reasons.add("connected")
            if (waitFlag) reasons.add("wait_flag")
            if (traced) reasons.add("tracer_pid")
            details?.add("debugger:${reasons.joinToString(",")}")
        }
        return detected
    }

    // ── Debuggable build detection ──────────────────────────────────────

    private fun isDebuggableBuild(context: Context, details: MutableList<String>?): Boolean {
        val debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (debuggable) details?.add("build:debuggable_flag_set")
        return debuggable
    }

    // ── Suspicious package detection ────────────────────────────────────

    private val SUSPICIOUS_PACKAGES = listOf(
        // Root managers
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        // Hooking frameworks
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        "io.github.lsposed.manager",
        "com.saurik.substrate",
        // Reverse engineering tools
        "com.topjohnwu.magisk.debug",
        "org.meowcat.edxposed.manager",
    )

    private fun detectSuspiciousPackages(context: Context, details: MutableList<String>?): List<String> {
        val found = mutableListOf<String>()
        val pm = context.packageManager
        for (pkg in SUSPICIOUS_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                found.add(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // Not installed, good
            }
        }
        if (found.isNotEmpty()) {
            details?.add("packages:${found.joinToString(",")}")
        }
        return found
    }

    // ═══════════════════════════════════════════════════════════════════
    // Internal check implementations
    // ═══════════════════════════════════════════════════════════════════

    private fun checkRootFiles(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkSuExists(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val br = BufferedReader(InputStreamReader(process.inputStream))
            br.readLine() != null
        } catch (_: Throwable) { false }
        finally { process?.destroy() }
    }

    private fun checkRootBuildTags(): Boolean {
        return Build.TAGS?.contains("test-keys") == true
    }

    private fun checkMagisk(): Boolean {
        val magiskPaths = arrayOf(
            "/sbin/magisk", "/system/xbin/magisk",
            "/data/adb/magisk", "/data/adb/modules",
            "/init.magisk.rc", "/cache/magisk.log",
            "/data/adb/magisk.db"
        )
        if (magiskPaths.any { File(it).exists() }) return true

        // Check for Magisk property
        return checkSystemProperty("ro.magisk.version") ||
               checkSystemProperty("persist.magisk.hide")
    }

    private fun checkKernelSU(): Boolean {
        val paths = arrayOf("/data/adb/ksud", "/data/adb/ksu")
        if (paths.any { File(it).exists() }) return true
        return checkSystemProperty("ro.kernelsu.version")
    }

    private fun checkRootProperties(): Boolean {
        val dangerousProps = listOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "service.adb.root" to "1"
        )
        return dangerousProps.any { (prop, expected) ->
            getSystemProperty(prop) == expected
        }
    }

    private fun checkMountNamespaces(): Boolean {
        // Detect overlayfs / bind mounts used by root cloaking
        return try {
            val file = File("/proc/self/mountinfo")
            if (!file.exists()) return false
            val reader = BufferedReader(FileReader(file))
            var detected = false
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val l = line ?: continue
                if (l.contains("magisk") || l.contains("ksu_overlay") || l.contains("tmpfs /system")) {
                    detected = true
                    break
                }
            }
            reader.close()
            detected
        } catch (_: Exception) { false }
    }

    private fun checkFridaPorts(): Boolean {
        val ports = intArrayOf(27042, 27043)
        return ports.any { port ->
            try {
                java.net.Socket("127.0.0.1", port).use { true }
            } catch (_: Exception) { false }
        }
    }

    private fun checkFridaMaps(): Boolean {
        return scanProcMaps(listOf("frida-agent", "gum-js-loop", "frida-gadget"))
    }

    private fun checkFridaGadget(): Boolean {
        // Frida Gadget is often injected as a shared library
        return scanProcMaps(listOf("libgadget", "frida-gadget", "re.frida.server"))
    }

    private fun checkXposedClasses(): Boolean {
        val suspicious = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
            "org.lsposed.lspd.core",
            "io.github.libxposed.api.XposedModule",
            "org.meowcat.edxposed.core"
        )
        return suspicious.any { name ->
            try { Class.forName(name); true } catch (_: ClassNotFoundException) { false }
        }
    }

    private fun checkSubstrate(): Boolean {
        return try {
            Class.forName("com.saurik.substrate.MS")
            true
        } catch (_: ClassNotFoundException) {
            scanProcMaps(listOf("com.saurik.substrate", "libsubstrate"))
        }
    }

    private fun checkNativeHookLibraries(): Boolean {
        return scanProcMaps(listOf(
            "libdexposed", "libepic", "libart_proxy",
            "libsandhook", "libpine", "libandfix"
        ))
    }

    private fun checkTracerPid(): Boolean {
        return try {
            val file = File("/proc/self/status")
            if (!file.exists()) return false
            BufferedReader(FileReader(file)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line ?: continue
                    if (l.startsWith("TracerPid:")) {
                        val pid = l.substringAfter("TracerPid:").trim().toIntOrNull() ?: 0
                        return pid != 0
                    }
                }
            }
            false
        } catch (_: Exception) { false }
    }

    // ── Advanced root-cloaking detection ────────────────────────────────

    private fun checkSELinuxPermissive(): Boolean {
        return try {
            val enforceFile = File("/sys/fs/selinux/enforce")
            if (!enforceFile.exists()) return false
            val value = BufferedReader(FileReader(enforceFile)).use { it.readLine()?.trim() }
            // "0" = permissive (suspicious), "1" = enforcing (normal)
            value == "0"
        } catch (_: Exception) { false }
    }

    private fun checkZygiskDenyList(): Boolean {
        val zygiskPaths = arrayOf(
            "/data/adb/modules/zygisksu",
            "/data/adb/modules/shamiko",
            "/data/adb/lspd",
            "/data/adb/modules/riru_lsposed",
            "/data/adb/modules/zygisk_lsposed",
            "/data/adb/magisk/denylist",
            "/data/adb/modules/playintegrityfix"
        )
        return zygiskPaths.any { File(it).exists() }
    }

    private fun checkProcAccessibility(): Boolean {
        // Root cloakers may restrict /proc access; if we CAN'T read what should
        // be readable, something is hiding data from us.
        return try {
            val maps = File("/proc/self/maps")
            val status = File("/proc/self/status")
            val mountinfo = File("/proc/self/mountinfo")
            // All three should be readable on a normal device
            if (!maps.canRead() || !status.canRead() || !mountinfo.canRead()) return true
            // Additionally, if maps is suspiciously small (< 50 lines), it may be filtered
            val lineCount = BufferedReader(FileReader(maps)).use { reader ->
                var count = 0
                while (reader.readLine() != null) count++
                count
            }
            lineCount < 20 // A normal process has many more mapped regions
        } catch (_: Exception) { false }
    }

    private fun checkNativeProperties(): Boolean {
        // Read properties via Android's SystemProperties class (reflection) to bypass
        // hooked getprop binary. Complements checkRootProperties() which uses getprop.
        return try {
            val systemProperties = Class.forName("android.os.SystemProperties")
            val getMethod = systemProperties.getMethod("get", String::class.java, String::class.java)
            val debuggable = getMethod.invoke(null, "ro.debuggable", "0") as String
            val secure = getMethod.invoke(null, "ro.secure", "1") as String
            val adbRoot = getMethod.invoke(null, "service.adb.root", "0") as String
            val magiskVersion = getMethod.invoke(null, "ro.magisk.version", "") as String
            val ksuVersion = getMethod.invoke(null, "ro.kernelsu.version", "") as String
            debuggable == "1" || secure == "0" || adbRoot == "1" ||
                magiskVersion.isNotEmpty() || ksuVersion.isNotEmpty()
        } catch (_: Exception) { false }
    }

    // ── Advanced hook detection ─────────────────────────────────────────

    private fun checkFridaThreadNames(): Boolean {
        // Frida injects threads with recognizable names that are harder to
        // rename than file-path artifacts.
        return try {
            val taskDir = File("/proc/self/task")
            if (!taskDir.exists() || !taskDir.isDirectory) return false
            val suspiciousNames = listOf("gmain", "gdbus", "gum-js-loop", "frida", "linjector")
            val dirs = taskDir.listFiles() ?: return false
            for (tid in dirs) {
                val commFile = File(tid, "comm")
                if (!commFile.exists()) continue
                try {
                    val threadName = BufferedReader(FileReader(commFile)).use {
                        it.readLine()?.trim()?.lowercase()
                    } ?: continue
                    if (suspiciousNames.any { threadName.contains(it) }) return true
                } catch (_: Exception) { continue }
            }
            false
        } catch (_: Exception) { false }
    }

    private fun checkFridaPortRange(): Boolean {
        // Scan beyond the default Frida ports (27042-27043) to catch
        // non-default configurations in the 27000-27100 range.
        return try {
            for (port in 27000..27100) {
                if (port == 27042 || port == 27043) continue // Already checked by checkFridaPorts
                try {
                    java.net.Socket().use { socket ->
                        socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 50)
                        // Connected — check if it speaks the Frida D-Bus protocol
                        val output = socket.getOutputStream()
                        // Send AUTH handshake: null byte + "AUTH\r\n" (D-Bus auth start)
                        output.write(0)
                        output.write("AUTH\r\n".toByteArray())
                        output.flush()
                        socket.soTimeout = 100
                        val input = socket.getInputStream()
                        val buf = ByteArray(128)
                        val read = try { input.read(buf) } catch (_: Exception) { -1 }
                        if (read > 0) {
                            val response = String(buf, 0, read)
                            // D-Bus responses start with "REJECTED" or "OK"
                            if (response.contains("REJECTED") || response.contains("OK")) return true
                        }
                    }
                } catch (_: Exception) { /* Port closed or no response */ }
            }
            false
        } catch (_: Exception) { false }
    }

    private fun checkSuspiciousFileDescriptors(): Boolean {
        // Scan /proc/self/fd symlinks for paths containing frida/injection artifacts
        return try {
            val fdDir = File("/proc/self/fd")
            if (!fdDir.exists() || !fdDir.isDirectory) return false
            val suspiciousTokens = listOf("frida", "gadget", "linjector", "xposed", "substrate")
            val fds = fdDir.listFiles() ?: return false
            for (fd in fds) {
                try {
                    // readlink via canonical path
                    val target = fd.canonicalPath.lowercase()
                    if (suspiciousTokens.any { target.contains(it) }) return true
                } catch (_: Exception) { continue }
            }
            false
        } catch (_: Exception) { false }
    }

    private fun checkProcessNameIntegrity(): Boolean {
        // Compare /proc/self/cmdline with what the Android framework thinks
        // the process name is. A mismatch indicates process injection.
        return try {
            val cmdlineFile = File("/proc/self/cmdline")
            if (!cmdlineFile.exists()) return false
            val raw = cmdlineFile.readBytes()
            // cmdline is null-terminated; take up to first null
            val nullIdx = raw.indexOf(0.toByte())
            val cmdline = if (nullIdx >= 0) String(raw, 0, nullIdx) else String(raw)
            // On Android, the cmdline should match the package name
            // Use Application.getProcessName() via reflection (API 28+)
            val appClass = Class.forName("android.app.Application")
            val getProcessName = try {
                appClass.getMethod("getProcessName")
            } catch (_: NoSuchMethodException) { return false }
            val processName = getProcessName.invoke(null) as? String ?: return false
            // If cmdline doesn't start with the process name, something is wrong
            !cmdline.startsWith(processName)
        } catch (_: Exception) { false }
    }

    // ── Utility helpers ─────────────────────────────────────────────────

    private fun scanProcMaps(keywords: List<String>): Boolean {
        return try {
            val file = File("/proc/self/maps")
            if (!file.exists()) return false
            BufferedReader(FileReader(file)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line?.lowercase() ?: continue
                    if (keywords.any { l.contains(it.lowercase()) }) return true
                }
            }
            false
        } catch (_: Exception) { false }
    }

    private fun getSystemProperty(prop: String): String? {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", prop))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim()
            process.destroy()
            value?.ifBlank { null }
        } catch (_: Exception) { null }
    }

    private fun checkSystemProperty(prop: String): Boolean {
        return getSystemProperty(prop) != null
    }
}
