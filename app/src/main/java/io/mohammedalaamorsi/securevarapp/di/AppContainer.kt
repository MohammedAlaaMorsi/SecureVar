package io.mohammedalaamorsi.securevarapp.di

import io.mohammedalaamorsi.securevarapp.data.remote.MockUserApi
import io.mohammedalaamorsi.securevarapp.data.remote.UserApi
import io.mohammedalaamorsi.securevarapp.data.repository.UserRepository
import io.mohammedalaamorsi.securevarapp.data.repository.UserRepositoryImpl
import io.mohammedalaamorsi.securevarapp.domain.manager.SessionManager
import android.content.Context
import io.mohammedalaamorsi.securevarapp.domain.usecase.LoginUseCase
import io.mohammedalaamorsi.securevarapp.domain.usecase.PurchaseSubscriptionUseCase
import io.mohammedalaamorsi.securevarapp.domain.usecase.RefreshUserStatusUseCase
import io.mohammedalaamorsi.securevarapp.presentation.SecureVarViewModel

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
    fun createSecureVarViewModel(): SecureVarViewModel {
        return SecureVarViewModel(
            sessionManager = sessionManager,
            loginUseCase = loginUseCase,
            purchaseSubscriptionUseCase = purchaseSubscriptionUseCase,
            refreshUserStatusUseCase = refreshUserStatusUseCase
        )
    }
}
