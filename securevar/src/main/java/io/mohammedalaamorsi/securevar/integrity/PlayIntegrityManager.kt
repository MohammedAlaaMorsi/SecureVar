package io.mohammedalaamorsi.securevar.integrity

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.gms.tasks.Tasks
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ExecutionException

/**
 * Manager for interacting with Google Play Integrity API.
 * This component retrieves the integrity token which should be sent to the backend for verification.
 * 
 * Note: A valid Google Cloud Project with Play Integrity API enabled is required.
 */
object PlayIntegrityManager {

    /**
     * Request an integrity token.
     * 
     * @param context Application context
     * @param nonce A unique nonce (likely from the server) to bind the token to the request.
     * @param cloudProjectNumber The Google Cloud Project Number (required for Standard Integrity API or classic).
     *                           For strict binding, use the server-generated nonce.
     * @return The Integrity Token string (Base64 Web Safe)
     * @throws Exception if token retrieval fails
     */
    suspend fun requestIntegrityToken(
        context: Context,
        nonce: String,
        cloudProjectNumber: Long
    ): String = withContext(Dispatchers.IO) {
        // Use the Standard Integrity API (or Classic, depending on needs).
        // For this example, we use the standard "IntegrityManager" which maps to the "Classic" API 
        // or "Standard" depending on updated library usage. 
        // But for simplicity in this demo, let's use the main entry point:
        
        val integrityManager = IntegrityManagerFactory.create(context)
        
        // Create the integrity token request
        val request = com.google.android.play.core.integrity.IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .setCloudProjectNumber(cloudProjectNumber)
            .build()
            
        try {
            val tokenResponse = Tasks.await(integrityManager.requestIntegrityToken(request))
            return@withContext tokenResponse.token()
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        } catch (e: Exception) {
            throw e
        }
    }
}
