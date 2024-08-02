package com.example.biometricsampleapp

import android.app.Application
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory.Companion.APPLICATION_KEY
import androidx.lifecycle.viewmodel.CreationExtras
import com.example.biometricsampleapp.biometric.BiometricHelper
import com.example.biometricsampleapp.biometric.SecurePreferences
import com.example.biometricsampleapp.data.model.LoggedInUser
import kotlin.math.log

class HomeScreenViewModel(val loggedInUser: LoggedInUser, application: Application) : AndroidViewModel(application = application) {

    val debugInfos = MutableLiveData("")

    val biometricHelper = BiometricHelper(application, loggedInUser.userId)

    val securePreferences = SecurePreferences(application, loggedInUser.userId)

    fun resetKeyStore() {
        securePreferences.clearEncryptedPin()
        biometricHelper.removeBiometricKey()
        getDebugInfos()
    }

    fun decryptDataTest(activity: FragmentActivity) {
        securePreferences.getEncryptedPin()?.let { encryptedPin ->
            biometricHelper.decryptePincodeBiometricPrompt(activity, encryptedPin) { result ->
                result.onSuccess {
                    debugInfos.value = "Decrypted pincode: $it"
                }
            }
        }

    }

    /**
     * For debugging purposes
     * check if biometric is available
     * check if pincode is saved
     * check if secure preferences is available
     * check if key is available
     */
    fun getDebugInfos() {
        debugInfos.value = "Biometric available: ${biometricHelper.getBiometricAvailabilityStatuses()}\n" +
                "Pincode saved: ${securePreferences.hasEncryptedPin()}\n" +
                "Secure preferences available: ${securePreferences.getEncryptedPin()}\n" +
                "Key available: ${biometricHelper.isBiometricKeyValid()}" +
                "Connected User ID: $loggedInUser"
    }

    // TODO: Implement the ViewModel
    companion object {
        fun provideFactory(loggedInUser: LoggedInUser): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                override fun <T : ViewModel> create(
                    modelClass: Class<T>,
                    extras: CreationExtras
                ): T {
                    if (modelClass.isAssignableFrom(HomeScreenViewModel::class.java)) {
                        val application = checkNotNull(extras[APPLICATION_KEY])
                        return HomeScreenViewModel(
                            loggedInUser,
                            application
                        ) as T
                    }
                    throw IllegalArgumentException("Unknown ViewModel class")
                }
            }
        }
    }

    init {
        getDebugInfos()
    }
}