package io.mohammedalaamorsi.trckqapp.di

import io.mohammedalaamorsi.trckqapp.data.remote.MockUserApi
import io.mohammedalaamorsi.trckqapp.data.remote.UserApi
import io.mohammedalaamorsi.trckqapp.data.repository.UserRepository
import io.mohammedalaamorsi.trckqapp.data.repository.UserRepositoryImpl
import io.mohammedalaamorsi.trckqapp.domain.manager.SessionManager
import android.content.Context
import io.mohammedalaamorsi.trckqapp.domain.usecase.LoginUseCase
import io.mohammedalaamorsi.trckqapp.domain.usecase.PurchaseSubscriptionUseCase
import io.mohammedalaamorsi.trckqapp.domain.usecase.RefreshUserStatusUseCase
import io.mohammedalaamorsi.trckqapp.presentation.TrckQViewModel

/**
 * Simple Dependency Injection container
 * In a real app, you'd use Dagger Hilt or Koin
 */
class AppContainer(private val appContext: Context) {
    
    // Data Layer
    private val userApi: UserApi = MockUserApi()
    private val userRepository: UserRepository = UserRepositoryImpl(userApi)
    
    // Domain Layer
    val sessionManager: SessionManager = SessionManager(userRepository, appContext)
    private val loginUseCase: LoginUseCase = LoginUseCase(sessionManager)
    private val purchaseSubscriptionUseCase: PurchaseSubscriptionUseCase = 
        PurchaseSubscriptionUseCase(sessionManager)
    private val refreshUserStatusUseCase: RefreshUserStatusUseCase = 
        RefreshUserStatusUseCase(sessionManager)
    
    // Presentation Layer
    fun createTrckQViewModel(): TrckQViewModel {
        return TrckQViewModel(
            sessionManager = sessionManager,
            loginUseCase = loginUseCase,
            purchaseSubscriptionUseCase = purchaseSubscriptionUseCase,
            refreshUserStatusUseCase = refreshUserStatusUseCase
        )
    }
}
