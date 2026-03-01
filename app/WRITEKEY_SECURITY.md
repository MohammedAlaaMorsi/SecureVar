# WriteKey Security System

## Overview

The enhanced `WriteKey` system provides cryptographic validation for secure variable writes with multiple layers of security:

1. **Nonce-based authentication** - One-time use keys
2. **Time-limited validity** - Keys expire after TTL
3. **Replay attack prevention** - Used nonces are tracked
4. **Signature verification** - Optional HMAC-like signatures
5. **Memory-efficient** - Automatic cleanup of old nonces

## Key Features

### 1. One-Time Use (Nonce)

Each `WriteKey` contains a unique nonce that can only be used once:

```kotlin
val key = WriteKey.generate()
key.isValid()  // ✓ First use succeeds
key.isValid()  // ✗ Second use fails - nonce already used
```

### 2. Time-Limited Validity

Keys expire after a configurable TTL (default: 5 minutes):

```kotlin
val key = WriteKey.generate(ttlMillis = 60_000) // 1 minute
Thread.sleep(61_000)
key.isValid()  // ✗ Expired
```

### 3. Signature Verification

Optional HMAC-like signatures prevent forgery:

```kotlin
val key = WriteKey.generate(secretKey = "backend-secret")
key.isValid(secretKey = "backend-secret")  // ✓ Valid
key.isValid(secretKey = "wrong-secret")    // ✗ Invalid
```

## Usage Patterns

### Server-Side (Backend)

```kotlin
// Server generates WriteKey after successful authentication/purchase
fun generateWriteKeyForUser(userId: String): UserProfileResponse {
    val writeKey = WriteKey.generate(
        secretKey = getServerSecretKey(),
        ttlMillis = 5 * 60 * 1000  // 5 minutes
    )
    
    return UserProfileResponse(
        userId = userId,
        isPremium = checkPremiumStatus(userId),
        writeKey = writeKey.nonce,
        writeKeyTimestamp = writeKey.timestamp,
        writeKeySignature = writeKey.signature
    )
}
```

### Client-Side (Android App)

```kotlin
// Client receives WriteKey from server
suspend fun login(email: String, password: String) {
    val response = api.login(email, password)
    
    // Reconstruct WriteKey from server response
    val writeKey = WriteKey(
        nonce = response.writeKey,
        timestamp = response.writeKeyTimestamp,
        signature = response.writeKeySignature
    )
    
    // Validate before use (optional but recommended)
    if (writeKey.validateAndLog()) {
        // Use the key to update secure variables
        isPremiumUserDelegate.authorizedWrite(
            newValue = response.isPremium,
            key = writeKey
        )
    }
}
```

## Security Mechanisms

### Replay Attack Prevention

```
Request 1: login() → Server generates key "abc123"
          Client uses "abc123" → ✓ Success (nonce added to used set)

Request 2: Attacker intercepts and replays "abc123"
          Client validates "abc123" → ✗ Rejected (nonce already used)
```

### Time-Based Expiration

```
t=0s    Server generates key (TTL = 5 min)
t=30s   Client receives key → ✓ Valid (4m 30s remaining)
t=2m    Client uses key → ✓ Valid (3m remaining)
t=6m    Attacker tries to reuse → ✗ Expired (past TTL)
```

### Signature Verification

```
Server:  message = "nonce123:1699564823"
         signature = HMAC(message, server_secret)
         sends: { nonce, timestamp, signature }

Client:  receives { nonce, timestamp, signature }
         recomputes: HMAC(nonce + timestamp, server_secret)
         compares with received signature
         ✓ Match → Valid | ✗ Mismatch → Forged
```

## API Reference

### WriteKey Constructor

```kotlin
WriteKey(
    nonce: String,                     // Required: unique identifier
    timestamp: Long = currentTime,     // Optional: creation time
    signature: String? = null,         // Optional: HMAC signature
    ttlMillis: Long = 5 * 60 * 1000   // Optional: time-to-live
)
```

### WriteKey.generate()

```kotlin
WriteKey.generate(
    secretKey: String = "app-secret-key",  // Secret for signature
    ttlMillis: Long = 5 * 60 * 1000       // Time-to-live
): WriteKey
```

### WriteKey.isValid()

```kotlin
fun isValid(secretKey: String = "app-secret-key"): Boolean
```

Validates the key and marks nonce as used if valid.

**Returns:** `true` if all checks pass:
- Nonce not blank
- Nonce not previously used
- Not expired
- Signature valid (if present)

### WriteKey.isExpired()

```kotlin
fun isExpired(): Boolean
```

Check expiration without consuming the key.

### WriteKey.isUsed()

```kotlin
fun isUsed(): Boolean
```

Check if nonce has been used.

## Security Best Practices

### ✅ DO

1. **Generate keys on the server** - Never generate keys client-side
2. **Use short TTLs** - 5 minutes or less for sensitive operations
3. **Always include signatures** - Prevents key forgery
4. **Validate before use** - Check `isValid()` before writing
5. **Use HTTPS** - Encrypt key transmission
6. **Rotate secrets** - Change server secret keys periodically

### ❌ DON'T

1. **Don't reuse nonces** - Each operation needs a fresh key
2. **Don't hardcode secrets** - Use secure storage (Android Keystore)
3. **Don't extend TTLs excessively** - Longer TTL = larger attack window
4. **Don't skip signature verification** - Always validate signatures
5. **Don't expose keys in logs** - Sensitive data
6. **Don't disable validation** - Every security layer matters

## Testing WriteKey

### Unit Test Example

```kotlin
@Test
fun testWriteKeyExpiration() {
    val key = WriteKey.generate(ttlMillis = 1000) // 1 second
    
    // Should be valid immediately
    assertTrue(key.isValid())
    
    // Create new key (previous is consumed)
    val key2 = WriteKey.generate(ttlMillis = 1000)
    Thread.sleep(1500) // Wait 1.5 seconds
    
    // Should be expired
    assertTrue(key2.isExpired())
    assertFalse(key2.isValid())
}

@Test
fun testReplayAttackPrevention() {
    val key = WriteKey.generate()
    
    // First use should succeed
    assertTrue(key.isValid())
    
    // Second use should fail
    assertFalse(key.isValid())
    assertTrue(key.isUsed())
}
```

### Integration Test Example

```kotlin
@Test
fun testEndToEndFlow() = runTest {
    // 1. Simulate server generating key
    val serverKey = WriteKey.generate(secretKey = "test-secret")
    
    // 2. Simulate sending to client (serialize)
    val nonce = serverKey.nonce
    val timestamp = serverKey.timestamp
    val signature = serverKey.signature
    
    // 3. Client reconstructs key
    val clientKey = WriteKey(nonce, timestamp, signature)
    
    // 4. Client validates
    assertTrue(clientKey.isValid(secretKey = "test-secret"))
    
    // 5. Client uses key to write
    testPropertyDelegate.authorizedWrite(
        newValue = true,
        key = clientKey
    )
    
    // 6. Verify write succeeded
    assertTrue(testProperty)
}
```

## Performance Considerations

### Memory Usage

- Each nonce consumes ~50-100 bytes
- Cache limited to 1000 nonces (configurable)
- Automatic cleanup when cache is full
- In production, consider using LRU cache with TTL-based eviction

### CPU Usage

- Signature generation: ~0.1ms per key
- Validation: ~0.1ms per key
- Negligible overhead for typical usage

### Recommendations

- For high-throughput apps: Implement distributed nonce tracking (Redis)
- For offline apps: Store used nonces in encrypted database
- For multi-process apps: Use shared preferences or content provider

## Migration Guide

### From Simple WriteKey

```kotlin
// Old way (simple nonce only)
val oldKey = WriteKey(nonce = "abc123")

// New way (with all features)
val newKey = WriteKey.generate()
```

### Backward Compatibility

The new system is **100% backward compatible**:

```kotlin
// This still works
val simpleKey = WriteKey(nonce = "simple-nonce")
simpleKey.isValid()  // ✓ Valid (signature optional)
```

## Troubleshooting

### Key Always Invalid

**Problem:** `isValid()` always returns `false`

**Solutions:**
1. Check if nonce is empty
2. Verify key hasn't expired
3. Confirm secret key matches server's
4. Ensure nonce hasn't been used before

### Replay Attack False Positives

**Problem:** Legitimate requests flagged as replays

**Solutions:**
1. Don't reuse the same WriteKey instance
2. Request fresh key from server for each operation
3. Clear nonce cache if needed: `WriteKey.cleanupExpiredNonces()`

### Memory Leak Concerns

**Problem:** Nonce cache growing indefinitely

**Solutions:**
1. Automatic cleanup at 1000 nonces (default)
2. Manual cleanup: `WriteKey.cleanupExpiredNonces()`
3. Implement custom cache with TTL-based eviction

## Advanced Usage

### Custom TTL per Operation

```kotlin
// Short-lived key for sensitive operations
val paymentKey = WriteKey.generate(ttlMillis = 60_000) // 1 minute

// Longer-lived key for less sensitive operations  
val profileKey = WriteKey.generate(ttlMillis = 10 * 60_000) // 10 minutes
```

### Pre-validation

```kotlin
// Check key validity before expensive operations
if (writeKey.isExpired()) {
    // Request fresh key from server
    writeKey = requestNewKey()
}

// Proceed with operation
propertyDelegate.authorizedWrite(value, writeKey)
```

### Logging and Monitoring

```kotlin
// Use extension for detailed logging
val isValid = writeKey.validateAndLog()

// Output:
// ✅ WriteKey Valid: abc123def456...
// OR
// 🚨 WriteKey Validation Failed: Nonce already used
//    Nonce: abc123def456...
//    Timestamp: 1699564823000
//    Age: 30500ms
//    Expired: false
//    Used: true
```

## See Also

- [SecureVarDelegate Documentation](../ARCHITECTURE.md)
- [SessionManager Usage Example](../README.md)
- [Security Best Practices](../QUICKSTART.md)
