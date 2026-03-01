plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.maven.publish)
}

android {
    namespace = "io.mohammedalaamorsi.securevar"
    compileSdk = 36

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {
    // Core Android KTX (used for SharedPreferences.edit{} extension)
    implementation(libs.androidx.core.ktx)
    
    // Kotlin reflection for property delegate access
    implementation(libs.kotlin.reflect)
    
    // Nonce persistence via DataStore
    implementation(libs.androidx.datastore.preferences)
    
    // Coroutines for async nonce store operations
    implementation(libs.kotlinx.coroutines.android)
    
    // Google Play Integrity API for device attestation
    implementation(libs.play.integrity)
    
    // Tink encryption for EncryptedDataStore (AES-GCM)
    implementation(libs.tink.android)
    
    // Test dependencies
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
