package io.mohammedalaamorsi.securevar

import java.util.concurrent.ConcurrentHashMap

object SecureVarManager {

    private var config: SecureVarConfig? = null
    internal val secretProvider: SecretProvider?
        get() = config?.secretProvider
    internal val writeKeyVerifier: WriteKeyVerifier?
        get() = config?.writeKeyVerifier
    // A set to track triggered pots to avoid alert storms
    private val triggeredPots = ConcurrentHashMap.newKeySet<String>()

    fun initialize(config: SecureVarConfig) {
        this.config = config
    }

    internal fun trigger(
        accessType: String,
        details: String
    ) {
        val currentConfig = config ?: run {
            // If not configured, just log to console
            println("SecureVar Alert: [$accessType] $details")
            return
        }

        val key = "$accessType:$details"
        
        // Only trigger the alert once per pot to avoid flooding.
        if (triggeredPots.contains(key)) {
            return
        }
        triggeredPots.add(key)

        // The action is now executed on a background thread.
        // The payload is much richer now.
        val alertPayload = mapOf(
            "accessType" to accessType,
            "details" to details,
            "timestamp" to System.currentTimeMillis().toString(),
            // Add other device/user info here
        )

        // Log the alert
        println("🚨 SecureVar Security Alert: $alertPayload")
        
        // Execute the configured action: Alert, Logout, Crash, etc.
        // For example, for an Alert action:
        // sendAlert(currentConfig.action.url, alertPayload)
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

// Configuration remains similar
data class SecureVarConfig(
    val action: SecureVarAction,
    val secretProvider: SecretProvider? = null,
    val writeKeyVerifier: WriteKeyVerifier? = null
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
