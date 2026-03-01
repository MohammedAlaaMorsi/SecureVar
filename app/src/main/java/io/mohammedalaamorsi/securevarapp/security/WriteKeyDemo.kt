package io.mohammedalaamorsi.securevarapp.security

import io.mohammedalaamorsi.securevar.WriteKey
import io.mohammedalaamorsi.securevar.ageSeconds
import io.mohammedalaamorsi.securevar.remainingTtlSeconds
import io.mohammedalaamorsi.securevar.validateAndLog

/**
 * WriteKeyDemo - Demonstrates all WriteKey security features
 * 
 * Run these examples to understand how the enhanced WriteKey system works
 */
object WriteKeyDemo {
    
    /**
     * Demo 1: Basic WriteKey validation
     */
    fun demo1_BasicValidation() {
        println("\n=== Demo 1: Basic WriteKey Validation ===")
        
        // Create a simple key (backward compatible with old API)
        val key1 = WriteKey(nonce = "simple-nonce-123")
        println("Key with just nonce: ${key1.isValid()}")
        
        // Create a key with signature
        val key2 = WriteKey.generate()
        println("Generated key: ${key2.isValid()}")
    }
    
    /**
     * Demo 2: Nonce replay attack prevention
     */
    fun demo2_ReplayAttackPrevention() {
        println("\n=== Demo 2: Replay Attack Prevention ===")
        
        val key = WriteKey.generate()
        
        // First use - should succeed
        println("First use: ${key.isValid()}")
        
        // Second use - should fail (nonce already used)
        println("Second use (replay attack): ${key.isValid()}")
        println("Is used? ${key.isUsed()}")
    }
    
    /**
     * Demo 3: Time-based expiration
     */
    fun demo3_TimeExpiration() {
        println("\n=== Demo 3: Time-Based Expiration ===")
        
        // Create a key that expires in 1 second
        val shortLivedKey = WriteKey.generate(ttlMillis = 1000)
        
        println("Key age: ${shortLivedKey.ageSeconds()}s")
        println("Remaining TTL: ${shortLivedKey.remainingTtlSeconds()}s")
        println("Is expired? ${shortLivedKey.isExpired()}")
        
        // Wait 1.5 seconds
        Thread.sleep(1500)
        
        println("After 1.5 seconds:")
        println("Key age: ${shortLivedKey.ageSeconds()}s")
        println("Remaining TTL: ${shortLivedKey.remainingTtlSeconds()}s")
        println("Is expired? ${shortLivedKey.isExpired()}")
        println("Is valid? ${shortLivedKey.isValid()}")
    }
    
    /**
     * Demo 4: Signature verification
     */
    fun demo4_SignatureVerification() {
        println("\n=== Demo 4: Signature Verification ===")
        
        // Generate key with correct signature
        val validKey = WriteKey.generate(secretKey = "secret123")
        println("Valid key: ${validKey.isValid(secretKey = "secret123")}")
        
        // Try to validate with wrong secret
        println("Wrong secret: ${validKey.isValid(secretKey = "wrong-secret")}")
        
        // Manually create key with invalid signature
        val tamperedKey = WriteKey(
            nonce = validKey.nonce,
            timestamp = validKey.timestamp,
            signature = "fake-signature-xxx"
        )
        println("Tampered signature: ${tamperedKey.isValid(secretKey = "secret123")}")
    }
    
    /**
     * Demo 5: Server response simulation
     */
    fun demo5_ServerResponseSimulation() {
        println("\n=== Demo 5: Server Response Simulation ===")
        
        // Simulate server generating a WriteKey
        println("Server generates WriteKey...")
        val serverKey = WriteKey.generate(
            secretKey = "backend-secret-key",
            ttlMillis = 5 * 60 * 1000 // 5 minutes
        )
        
        println("Server sends to client:")
        println("  Nonce: ${serverKey.nonce}")
        println("  Timestamp: ${serverKey.timestamp}")
        println("  Signature: ${serverKey.signature}")
        println("  TTL: ${serverKey.ttlMillis}ms (${serverKey.ttlMillis / 1000}s)")
        
        // Client validates the key
        /*println("\nClient validates key:")
        val result = WriteKeyValidator.validate(serverKey)
        println("  Valid: $isValid")
        println("  Reason: $reason")
        
        // Client uses the key
        if (isValid) {
            println("\n✅ Client can now use this key to write to secure variables")
            println("   secureVar(::isPremiumUser).write(true, serverKey)")
        }*/
    }
    
    /**
     * Demo 6: Attack scenarios
     */
    fun demo6_AttackScenarios() {
        println("\n=== Demo 6: Attack Scenarios ===")
        
        // Scenario 1: Attacker tries to reuse old nonce
        println("\nScenario 1: Replay Attack")
        val legitimateKey = WriteKey.generate()
        println("Legitimate first use: ${legitimateKey.isValid()}")
        println("Attacker reuses nonce: ${legitimateKey.isValid()}")
        
        // Scenario 2: Attacker tries to use expired key
        println("\nScenario 2: Expired Key")
        val oldKey = WriteKey(
            nonce = "old-nonce",
            timestamp = System.currentTimeMillis() - (10 * 60 * 1000), // 10 min ago
            ttlMillis = 5 * 60 * 1000 // 5 min TTL
        )
        println("Old key age: ${oldKey.ageSeconds()}s")
        println("Is valid? ${oldKey.isValid()}")
        
        // Scenario 3: Attacker forges signature
        println("\nScenario 3: Forged Signature")
        val forgedKey = WriteKey(
            nonce = "attacker-nonce",
            timestamp = System.currentTimeMillis(),
            signature = "forged-signature-12345"
        )
        println("Forged key valid? ${forgedKey.isValid()}")
    }
    
    /**
     * Run all demos
     */
    fun runAllDemos() {
        demo1_BasicValidation()
        demo2_ReplayAttackPrevention()
        demo3_TimeExpiration()
        demo4_SignatureVerification()
        demo5_ServerResponseSimulation()
        demo6_AttackScenarios()
        
        println("\n" + "=".repeat(50))
        println("All demos completed!")
    }
}

/**
 * Usage example in your app:
 * 
 * ```kotlin
 * // In your Application class or test
 * WriteKeyDemo.runAllDemos()
 * ```
 */
