package io.mohammedalaamorsi.securevarapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import io.mohammedalaamorsi.securevarapp.ui.theme.SecureVarTheme
import io.mohammedalaamorsi.securevarapp.presentation.SecureVarScreen

class SecureVarActivity : ComponentActivity() {
    
    private lateinit var viewModel: io.mohammedalaamorsi.securevarapp.presentation.SecureVarViewModel
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Get the application container
        val appContainer = (application as SecureVarApplication).appContainer
        
        // Create ViewModel (in a real app, use ViewModelFactory)
        viewModel = appContainer.createSecureVarViewModel()
        
        enableEdgeToEdge()
        setContent {
            SecureVarTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SecureVarScreen(viewModel = viewModel)
                }
            }
        }
    }
}
