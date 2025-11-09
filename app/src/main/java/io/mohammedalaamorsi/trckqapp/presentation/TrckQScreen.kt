package io.mohammedalaamorsi.trckqapp.presentation

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun TrckQScreen(viewModel: TrckQViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val message by viewModel.message.collectAsState()

    // Show snackbar for messages
    val snackbarHostState = remember { SnackbarHostState() }
    
    LaunchedEffect(message) {
        message?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessage()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "TrckQ Secure Variable Demo",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(vertical = 16.dp)
            )

            when (val state = uiState) {
                is TrckQViewModel.UiState.LoggedOut -> {
                    LoggedOutContent(
                        onLogin = { email, password ->
                            viewModel.login(email, password)
                        }
                    )
                }
                is TrckQViewModel.UiState.Loading -> {
                    LoadingContent()
                }
                is TrckQViewModel.UiState.LoggedIn -> {
                    LoggedInContent(
                        username = state.username,
                        isPremium = state.isPremium,
                        onPurchase = { viewModel.purchaseSubscription() },
                        onRefresh = { viewModel.refreshStatus() },
                        onAttemptHack = { viewModel.attemptHack() }
                    )
                }
                is TrckQViewModel.UiState.Error -> {
                    ErrorContent(message = state.message)
                }
            }
        }
    }
}

@Composable
fun LoggedOutContent(onLogin: (String, String) -> Unit) {
    var email by remember { mutableStateOf("user@example.com") }
    var password by remember { mutableStateOf("password123") }

    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Login",
                fontSize = 20.sp,
                fontWeight = FontWeight.SemiBold
            )

            OutlinedTextField(
                value = email,
                onValueChange = { email = it },
                label = { Text("Email") },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password") },
                modifier = Modifier.fillMaxWidth()
            )

            Button(
                onClick = { onLogin(email, password) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Login")
            }
        }
    }
}

@Composable
fun LoadingContent() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator()
    }
}

@Composable
fun LoggedInContent(
    username: String,
    isPremium: Boolean,
    onPurchase: () -> Unit,
    onRefresh: () -> Unit,
    onAttemptHack: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isPremium) 
                MaterialTheme.colorScheme.primaryContainer 
            else 
                MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "User Status",
                fontSize = 20.sp,
                fontWeight = FontWeight.SemiBold
            )

            Divider()

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Username:", fontWeight = FontWeight.Medium)
                Text(username)
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Premium Status:", fontWeight = FontWeight.Medium)
                Text(
                    text = if (isPremium) "✓ PREMIUM" else "FREE",
                    color = if (isPremium) 
                        MaterialTheme.colorScheme.primary 
                    else 
                        MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }

    if (!isPremium) {
        Button(
            onClick = onPurchase,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Purchase Premium Subscription")
        }
    }

    Button(
        onClick = onRefresh,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text("Refresh User Status")
    }

    Divider(modifier = Modifier.padding(vertical = 8.dp))

    Text(
        text = "Security Test",
        fontSize = 18.sp,
        fontWeight = FontWeight.SemiBold
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "⚠️ Tamper Detection Demo",
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            
            Text(
                text = "This button simulates a hack attempt to directly modify the isPremiumUser variable. The secure variable system will detect and block this.",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onErrorContainer
            )

            Button(
                onClick = onAttemptHack,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Attempt Unauthorized Write")
            }
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "ℹ️ How It Works",
                fontWeight = FontWeight.Medium
            )
            
            Text(
                text = "• Server is the source of truth\n" +
                        "• Each API response includes a one-time write key\n" +
                        "• Only authorized writes with valid keys succeed\n" +
                        "• Direct assignments trigger security alerts\n" +
                        "• Values are obfuscated and tamper-detected",
                fontSize = 12.sp
            )
        }
    }
}

@Composable
fun ErrorContent(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Error",
                fontSize = 20.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            Text(
                text = message,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
        }
    }
}
