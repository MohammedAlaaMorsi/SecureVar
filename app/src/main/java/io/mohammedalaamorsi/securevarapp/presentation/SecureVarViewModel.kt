package io.mohammedalaamorsi.securevarapp.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.mohammedalaamorsi.securevarapp.domain.manager.SessionManager
import io.mohammedalaamorsi.securevarapp.domain.usecase.LoginUseCase
import io.mohammedalaamorsi.securevarapp.domain.usecase.PurchaseSubscriptionUseCase
import io.mohammedalaamorsi.securevarapp.domain.usecase.RefreshUserStatusUseCase
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for the main screen
 * Handles UI state and business logic coordination
 */
class SecureVarViewModel(
    private val sessionManager: SessionManager,
    private val loginUseCase: LoginUseCase,
    private val purchaseSubscriptionUseCase: PurchaseSubscriptionUseCase,
    private val refreshUserStatusUseCase: RefreshUserStatusUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow<UiState>(UiState.LoggedOut)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    fun login(email: String, password: String) {
        viewModelScope.launch {
            _uiState.value = UiState.Loading
            
            loginUseCase(email, password)
                .onSuccess {
                    _uiState.value = UiState.LoggedIn(
                        username = sessionManager.username,
                        isPremium = sessionManager.isPremiumUser
                    )
                    _message.value = "Login successful!"
                }
                .onFailure { error ->
                    _uiState.value = UiState.Error(error.message ?: "Login failed")
                    _message.value = "Login failed: ${error.message}"
                }
        }
    }

    fun purchaseSubscription() {
        viewModelScope.launch {
            _uiState.value = UiState.Loading
            
            purchaseSubscriptionUseCase()
                .onSuccess {
                    _uiState.value = UiState.LoggedIn(
                        username = sessionManager.username,
                        isPremium = sessionManager.isPremiumUser
                    )
                    _message.value = "Subscription purchased successfully!"
                }
                .onFailure { error ->
                    _uiState.value = UiState.Error(error.message ?: "Purchase failed")
                    _message.value = "Purchase failed: ${error.message}"
                }
        }
    }

    fun refreshStatus() {
        viewModelScope.launch {
            refreshUserStatusUseCase()
                .onSuccess {
                    _uiState.value = UiState.LoggedIn(
                        username = sessionManager.username,
                        isPremium = sessionManager.isPremiumUser
                    )
                    _message.value = "Status refreshed!"
                }
                .onFailure { error ->
                    _message.value = "Refresh failed: ${error.message}"
                }
        }
    }

    fun attemptHack() {
        // This demonstrates what happens when someone tries to directly modify the secure variable
        // The secure delegate will ignore the write and trigger an internal alarm
        sessionManager.attemptDirectWrite()
        _message.value = "⚠️ Hack attempt detected! Secure write blocked and alert triggered."
    }

    fun clearMessage() {
        _message.value = null
    }

    sealed class UiState {
        object LoggedOut : UiState()
        object Loading : UiState()
        data class LoggedIn(val username: String, val isPremium: Boolean) : UiState()
        data class Error(val message: String) : UiState()
    }
}
