package io.mohammedalaamorsi.securevarapp.domain.usecase

import io.mohammedalaamorsi.securevarapp.domain.manager.SessionManager

/**
 * Use case for purchasing a subscription
 * Encapsulates the business logic for subscription purchase
 */
class PurchaseSubscriptionUseCase(private val sessionManager: SessionManager) {
    
    suspend operator fun invoke(): Result<Unit> {
        return sessionManager.purchaseSubscription()
    }
}
