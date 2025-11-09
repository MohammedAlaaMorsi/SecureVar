package io.mohammedalaamorsi.trckqapp.domain.usecase

import io.mohammedalaamorsi.trckqapp.domain.manager.SessionManager

/**
 * Use case for purchasing a subscription
 * Encapsulates the business logic for subscription purchase
 */
class PurchaseSubscriptionUseCase(private val sessionManager: SessionManager) {
    
    suspend operator fun invoke(): Result<Unit> {
        return sessionManager.purchaseSubscription()
    }
}
