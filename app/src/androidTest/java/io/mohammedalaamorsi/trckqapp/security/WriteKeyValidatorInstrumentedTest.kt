package io.mohammedalaamorsi.trckqapp.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.mohammedalaamorsi.trckqapp.data.remote.MockUserApi
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.After
import org.junit.Before

@RunWith(AndroidJUnit4::class)
class WriteKeyValidatorInstrumentedTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val api = MockUserApi()

    @Before
    fun setup() {
        WriteKeyValidator.testForceHighRisk(null) // normal risk by default
        WriteKeyValidator.testResetNonceStore(context)
    }

    @After
    fun tearDown() {
        WriteKeyValidator.testForceHighRisk(null)
        WriteKeyValidator.testResetNonceStore(context)
    }

    @Test
    fun asymmetricValidation_success_thenReplay() = runBlocking {
        val profile = api.login("test@example.com", "password")
        val key = WriteKeyValidator.fromServerResponse(
            nonce = profile.writeKey,
            timestamp = profile.writeKeyTimestamp,
            signature = profile.writeKeySignature,
            asymSignature = profile.writeKeyAsymSignature,
            userId = profile.userId,
            scope = profile.writeKeyScope,
            propertyName = profile.writeKeyScope
        )
        val result1 = WriteKeyValidator.validate(key, context)
        assertTrue(result1 is WriteKeyValidator.ValidationResult.Valid)

        // Replay should be detected now
        val result2 = WriteKeyValidator.validate(key, context)
        assertTrue(result2 is WriteKeyValidator.ValidationResult.Replay)
    }

    @Test
    fun asymmetricValidation_mismatch_detected() = runBlocking {
        val profile = api.fetchUserProfile()
        // Corrupt the asymmetric signature slightly
        val badAsym = profile.writeKeyAsymSignature?.let {
            if (it.isNotEmpty()) it.dropLast(1) + if (it.last() != 'A') 'A' else 'B' else null
        }
        val badKey = WriteKeyValidator.fromServerResponse(
            nonce = profile.writeKey,
            timestamp = profile.writeKeyTimestamp,
            signature = profile.writeKeySignature,
            asymSignature = badAsym,
            userId = profile.userId,
            scope = profile.writeKeyScope,
            propertyName = profile.writeKeyScope
        )
        val result = WriteKeyValidator.validate(badKey, context)
        assertTrue(result is WriteKeyValidator.ValidationResult.AsymSignatureMismatch)
    }

    @Test
    fun nonceStoreTamperDetected() = runBlocking {
        val p1 = api.purchaseSubscription("user-123")
        val key1 = WriteKeyValidator.fromServerResponse(
            nonce = p1.writeKey,
            timestamp = p1.writeKeyTimestamp,
            signature = p1.writeKeySignature,
            asymSignature = p1.writeKeyAsymSignature,
            userId = p1.userId,
            scope = p1.writeKeyScope,
            propertyName = p1.writeKeyScope
        )
        val r1 = WriteKeyValidator.validate(key1, context)
        assertTrue(r1 is WriteKeyValidator.ValidationResult.Valid)

        // Corrupt the MAC
        WriteKeyValidator.testCorruptNonceStoreMac(context)

        // Next validation attempt should detect tampering
        val p2 = api.fetchUserProfile()
        val key2 = WriteKeyValidator.fromServerResponse(
            nonce = p2.writeKey,
            timestamp = p2.writeKeyTimestamp,
            signature = p2.writeKeySignature,
            asymSignature = p2.writeKeyAsymSignature,
            userId = p2.userId,
            scope = p2.writeKeyScope,
            propertyName = p2.writeKeyScope
        )
        val r2 = WriteKeyValidator.validate(key2, context)
        assertTrue(r2 is WriteKeyValidator.ValidationResult.NonceStoreTampered)
    }

    @Test
    fun missingSignatureRejectedInHighRisk() = runBlocking {
        // Force high-risk posture
        WriteKeyValidator.testForceHighRisk(true)

        val profile = api.fetchUserProfile()
        // Create key without any signatures
        val key = WriteKeyValidator.fromServerResponse(
            nonce = profile.writeKey,
            timestamp = profile.writeKeyTimestamp,
            signature = null,
            asymSignature = null,
            userId = profile.userId,
            scope = profile.writeKeyScope,
            propertyName = profile.writeKeyScope
        )
        val result = WriteKeyValidator.validate(key, context)
        assertTrue(result is WriteKeyValidator.ValidationResult.InvalidFormat)
    }

    @Test
    fun hmacFallbackAcceptedWhenNotHighRisk() = runBlocking {
        // Ensure normal risk posture
        WriteKeyValidator.testForceHighRisk(false)
        val profile = api.fetchUserProfile()
        // Use only HMAC signature
        val key = WriteKeyValidator.fromServerResponse(
            nonce = profile.writeKey,
            timestamp = profile.writeKeyTimestamp,
            signature = profile.writeKeySignature,
            asymSignature = null,
            userId = profile.userId,
            scope = profile.writeKeyScope,
            propertyName = profile.writeKeyScope
        )
        val result = WriteKeyValidator.validate(key, context)
        assertTrue(result is WriteKeyValidator.ValidationResult.Valid)
    }

    @Test
    fun noSignatureAcceptedWhenNotHighRisk() = runBlocking {
        WriteKeyValidator.testForceHighRisk(false)
        val profile = api.login("sigless@example.com", "pw")
        val key = WriteKeyValidator.fromServerResponse(
            nonce = profile.writeKey,
            timestamp = profile.writeKeyTimestamp,
            signature = null,
            asymSignature = null,
            userId = profile.userId,
            scope = profile.writeKeyScope,
            propertyName = profile.writeKeyScope
        )
        val result = WriteKeyValidator.validate(key, context)
        assertTrue(result is WriteKeyValidator.ValidationResult.Valid)
    }

    @Test
    fun clockSkewExceededDetected() = runBlocking {
        WriteKeyValidator.testForceHighRisk(false)
        val profile = api.fetchUserProfile()
        val futureTs = System.currentTimeMillis() + 60_000L
        val key = WriteKeyValidator.fromServerResponse(
            nonce = profile.writeKey,
            timestamp = futureTs,
            signature = null,
            asymSignature = null,
            userId = profile.userId,
            scope = profile.writeKeyScope,
            propertyName = profile.writeKeyScope
        )
        val result = WriteKeyValidator.validate(key, context)
        assertTrue(result is WriteKeyValidator.ValidationResult.ClockSkewExceeded)
    }

    @Test
    fun asymmetricOnlyAccepted() = runBlocking {
        WriteKeyValidator.testForceHighRisk(false)
        val profile = api.fetchUserProfile()
        val key = WriteKeyValidator.fromServerResponse(
            nonce = profile.writeKey,
            timestamp = profile.writeKeyTimestamp,
            signature = null,
            asymSignature = profile.writeKeyAsymSignature,
            userId = profile.userId,
            scope = profile.writeKeyScope,
            propertyName = profile.writeKeyScope
        )
        val result = WriteKeyValidator.validate(key, context)
        assertTrue(result is WriteKeyValidator.ValidationResult.Valid)
    }
}
