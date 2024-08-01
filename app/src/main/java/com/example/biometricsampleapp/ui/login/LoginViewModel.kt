package com.example.biometricsampleapp.ui.login

import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import android.util.Patterns
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.CreationExtras
import com.example.biometricsampleapp.BiometricSampleApp
import com.example.biometricsampleapp.data.LoginRepository

import com.example.biometricsampleapp.R
import com.example.biometricsampleapp.biometric.BiometricAvailabilityStatuses
import com.example.biometricsampleapp.biometric.BiometricHelper
import com.example.biometricsampleapp.biometric.NoPinCodeSavedOnDeviceToAuthenticateWithException
import com.example.biometricsampleapp.biometric.SecurePreferences
import com.example.biometricsampleapp.data.LoginDataSource
import com.example.biometricsampleapp.data.model.LoggedInUser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


sealed class LoginUIState {
    data object Loading : LoginUIState()
    data class Attempted(val result: Result<LoggedInUser>, val shouldEnrollForBiometrics: Boolean = false) : LoginUIState()
    data object Idle: LoginUIState()
}
class LoginViewModel(application: BiometricSampleApp) : AndroidViewModel(application) {

    companion object {
        val Factory: ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(
                modelClass: Class<T>,
                extras: CreationExtras
            ): T {
                // Get the Application object from extras
                val application = checkNotNull(extras[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY])
                return LoginViewModel(
                    (application as BiometricSampleApp)
                ) as T
            }
        }
    }

    val uiState = MutableLiveData<LoginUIState>(LoginUIState.Idle)
    fun getUiState(): LiveData<LoginUIState> = uiState

    val loginFormState = MutableLiveData<LoginFormState>()
    fun getLoginFormState(): LiveData<LoginFormState> = loginFormState

    private val loginRepository = LoginRepository(LoginDataSource())

    private val biometricHelper = BiometricHelper(application, userId = "1")
    private val securePreferences = SecurePreferences(application, userId = "1")

    private val biometricAvailable = MutableLiveData<BiometricAvailabilityStatuses>()
    fun getBiometricAvailable(): LiveData<BiometricAvailabilityStatuses> = biometricAvailable

    private val canTriggerBiometricPrompt = MutableLiveData<Boolean>()
    fun getCanTriggerBiometricPrompt(): LiveData<Boolean> = canTriggerBiometricPrompt

    private var pincodeSavedForEnrollment: String? = null

    /**
     * For debugging purposes
     * check if biometric is available
     * check if pincode is saved
     * check if secure preferences is available
     * check if key is available
     */
    fun getDebugInfos(): String {
        return "Biometric available: ${biometricAvailable.value}\n" +
                "Pincode saved: ${securePreferences.hasEncryptedPin()}\n" +
                "Secure preferences available: ${securePreferences.getEncryptedPin()}\n" +
                "Key available: ${biometricHelper.isBiometricKeyValid()}"
    }


    init {

        checkBiometricSystemStatus()
        checkIfBiometricPromptCanBeTriggered()

    }

    fun checkIfBiometricPromptCanBeTriggered() {
        canTriggerBiometricPrompt.value = biometricHelper.isBiometricAvailable() && securePreferences.hasEncryptedPin() && biometricHelper.isBiometricKeyValid()
    }

    fun checkBiometricSystemStatus() {
        biometricAvailable.value = biometricHelper.getBiometricAvailabilityStatuses()
    }

    // We save pin code if server accepted it
    fun savePin(pin: String) {
        viewModelScope.launch {
            val encryptedPin = biometricHelper.encryptPin(pin)
            securePreferences.saveEncryptedPin(encryptedPin)
        }
    }

    fun loginWithBiometric(activity: FragmentActivity) {
        biometricHelper.showBiometricPrompt(activity) { result ->
            // L'utilisateur à réussi à vérifier son empreinte digitale
            result.onSuccess { pairOfData ->
                // On déchiffre le pincode stocké ici

                val cryptoObject = pairOfData.second
                val authenticationResult = pairOfData.first
                securePreferences.getEncryptedPin()?.let { encryptedPin ->
                    val decryptedPin = biometricHelper.decryptPin(encryptedPin, cryptoObject)

                    // Puis on se connecte avec le pincode déchiffré -- Serveur accepte ou non
                    viewModelScope.launch {
                        val userLoggedIn = loginRepository.loginWithPincode(decryptedPin)
                        delay(1500)

                        withContext(Dispatchers.Main) {
                            userLoggedIn.onSuccess { userLoggedData ->
                                uiState.value =
                                    LoginUIState.Attempted(Result.success(userLoggedData))
                            }

                            userLoggedIn.onFailure {
                                // L'utilisateur n'a pas réussi à se connecter avec le pincode sur le serveur
                                uiState.value = LoginUIState.Attempted(Result.failure(it))

                                // Il faudrait désactiver la biométrie pour la prochaine fois dans ce cas de figure
                            }
                        }
                    }
                } ?: run {
                    // L'utilisateur n'a pas de pincode enregistré
                    uiState.value = LoginUIState.Attempted(Result.failure(
                        NoPinCodeSavedOnDeviceToAuthenticateWithException()
                    ))
                }

            }

            result.onFailure {
                // L'utilisateur n'a pas réussi à vérifier son empreinte digitale
                uiState.value = LoginUIState.Attempted(Result.failure(it))
            }


            }
        }

    fun enrollForBiometric(activity: FragmentActivity) {
        pincodeSavedForEnrollment?.let {
            biometricHelper.offerBiometricEnrollment(activity, it) {
                it.onSuccess {

                }
            }
        } ?: run {
            // No pincode saved
            // Handle error here -> User should have a pincode saved before enrolling for biometrics
        }

    }

    fun login(pincode: String? = null, activity: FragmentActivity? = null) {
        uiState.value = LoginUIState.Loading
        // Todo:
        // 1. Check if keys exists for this user -> KeyStore and SecurePreferences
        // 2. Check if biometric is available
        // 3. Launch Biometric Prompt
        if (canTriggerBiometricPrompt.value == true && activity != null && pincode == null) {
            loginWithBiometric(activity)
            return
        }

        // Todo:
        // If nor 1 or 2 then we can launch the classic login with pincode
        // 1. User enter pincode
        // 2. Send to server for authentication
        // 3. If success, encrypt and save pincode in SecurePreferences
        // 4. Ask user if he wants to enable biometric for the next prompt
        // 5. If user accepts, create biometric key and save it in KeyStore, otherwise remove pincode from SecurePreferences

        pincode?.let { pincodeEntered ->
            // can be launched in a separate asynchronous job
            viewModelScope.launch {
                delay(2000)
                val result = loginRepository.loginWithPincode(pincodeEntered)

                result.onSuccess { user ->
                    if (biometricHelper.isBiometricAvailable() && (!securePreferences.hasEncryptedPin() || !biometricHelper.isBiometricKeyValid())) {
                        pincodeSavedForEnrollment = pincodeEntered
                        uiState.value = LoginUIState.Attempted(
                            Result.success(user),
                            shouldEnrollForBiometrics = true
                        )
                    } else {
                        // Classic login, but user cannot enroll for biometrics
                        uiState.value = LoginUIState.Attempted(Result.success(user))
                    }
                }

                result.onFailure { error ->
                    Log.w("LoginViewModel", "Error: $error")
                    uiState.value = LoginUIState.Attempted(Result.failure(error))
                }
            }
        }
    }

    fun loginDataChanged(pincode: String) {
         if (!isPasswordValid(pincode)) {
            loginFormState.value = LoginFormState(passwordError = R.string.invalid_password)
        } else {
            loginFormState.value = LoginFormState(isDataValid = true)
        }
    }

    // A placeholder username validation check
    private fun isUserNameValid(username: String): Boolean {
        return if (username.contains("@")) {
            Patterns.EMAIL_ADDRESS.matcher(username).matches()
        } else {
            username.isNotBlank()
        }
    }

    // A placeholder password validation check
    private fun isPasswordValid(password: String): Boolean {
        return password.length == 4
    }

    /**
     * Remove biometric data for the user
     * This will remove the biometric key and the encrypted pincode
     */
    fun removeBiometricDataForUser() {
        securePreferences.clearEncryptedPin()
        biometricHelper.removeBiometricKey()
    }
}