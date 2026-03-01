package io.mohammedalaamorsi.securevar

import io.mohammedalaamorsi.securevar.risk.RiskDetector
import io.mohammedalaamorsi.securevar.security.OriginVerifier
import java.util.concurrent.ConcurrentHashMap

object SecureVarManager {

    private var config: SecureVarConfig? = null
    internal val secretProvider: SecretProvider?
        get() = config?.secretProvider
    internal val writeKeyVerifier: WriteKeyVerifier?
        get() = config?.writeKeyVerifier
    internal val originVerifier: OriginVerifier?
        get() = config?.originVerifier
    internal val allowedCallerPackages: List<String>
        get() = config?.allowedCallerPackages ?: emptyList()

    // A set to track triggered pots to avoid alert storms
    private val triggeredPots = ConcurrentHashMap.newKeySet<String>()

    fun initialize(config: SecureVarConfig) {
        this.config = config
    }

    /**
     * Perform a runtime risk check and invoke the [SecureVarConfig.onRiskDetected]
     * callback if the device environment is high-risk.
     * Called automatically by [SecureVarDelegate.authorizedWrite] when a context is available.
     */
    internal fun checkRiskAndNotify() {
        val ctx = config?.context ?: return
        val callback = config?.onRiskDetected ?: return
        val report = RiskDetector.getDetailedRiskReport(ctx)
        if (report.highRisk) {
            callback.invoke(report)
        }
    }

    internal fun trigger(
        accessType: String,
        details: String
    ) {
        val currentConfig = config ?: run {
            println("SecureVar Alert: [$accessType] $details")
            return
        }

        val key = "$accessType:$details"
        
        // Only trigger the alert once per pot to avoid flooding.
        if (triggeredPots.contains(key)) {
            return
        }
        triggeredPots.add(key)

        val alertPayload = mapOf(
            "accessType" to accessType,
            "details" to details,
            "timestamp" to System.currentTimeMillis().toString(),
        )

        println("🚨 SecureVar Security Alert: $alertPayload")

        // Execute the configured action
        when (val action = currentConfig.action) {
            is SecureVarAction.Alert -> {
                // In production, send to action.url via HTTP
            }
            is SecureVarAction.Logout -> {
                // App should register a logout handler
            }
            is SecureVarAction.Crash -> {
                throw SecurityException("SecureVar: Tamper detected — $alertPayload")
            }
        }
    }
    
    // Legacy compatibility method
    internal fun trigger(
        potName: String,
        accessType: String,
        propertyName: String,
        className: String
    ) {
        trigger(accessType, "pot=$potName, property=$propertyName, class=$className")
    }
}

/**
 * Configuration for the SecureVar library.
 *
 * @param action           Action to take on tamper detection (Alert, Logout, Crash)
 * @param secretProvider   Provider for MAC/ENC secrets (backed by Keystore in production)
 * @param writeKeyVerifier Optional custom verifier for server-issued WriteKeys
 * @param originVerifier   Multi-signal origin verifier (stack trace + ClassLoader + APK signature)
 * @param allowedCallerPackages  Allowed calling package prefixes for simple stack-trace verification
 *                               (used as fallback when [originVerifier] is null)
 * @param context          Application context for runtime risk detection
 * @param onRiskDetected   Callback invoked when a high-risk environment is detected during write
 */
data class SecureVarConfig(
    val action: SecureVarAction,
    val secretProvider: SecretProvider? = null,
    val writeKeyVerifier: WriteKeyVerifier? = null,
    val originVerifier: OriginVerifier? = null,
    val allowedCallerPackages: List<String> = emptyList(),
    val context: android.content.Context? = null,
    val onRiskDetected: ((RiskDetector.RiskReport) -> Unit)? = null
)

sealed class SecureVarAction {
    data class Alert(val url: String) : SecureVarAction()
    object Logout : SecureVarAction()
    object Crash : SecureVarAction()
}

/** Provider for MAC/ENC secrets. In production, back this with Android Keystore/EncryptedSharedPreferences. */
interface SecretProvider {
    fun getMacSecret(): String
    fun getEncSecret(propertyName: String): String
}

/** Optional verifier for server-issued WriteKeys. App can plug in its own validator. */
fun interface WriteKeyVerifier {
    fun verify(key: WriteKey): Boolean
}
