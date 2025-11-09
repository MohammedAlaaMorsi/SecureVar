package io.mohammedalaamorsi.trckqapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import io.mohammedalaamorsi.trckqapp.ui.theme.TrckQTheme
import io.mohammedalaamorsi.trckqapp.presentation.MainScreen

class MainActivity : ComponentActivity() {
    
    private lateinit var viewModel: io.mohammedalaamorsi.trckqapp.presentation.MainViewModel
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Get the application container
        val appContainer = (application as TrckQApplication).appContainer
        
        // Create ViewModel (in a real app, use ViewModelFactory)
        viewModel = appContainer.createMainViewModel()
        
        enableEdgeToEdge()
        setContent {
            TrckQTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(viewModel = viewModel)
                }
            }
        }
    }
}
