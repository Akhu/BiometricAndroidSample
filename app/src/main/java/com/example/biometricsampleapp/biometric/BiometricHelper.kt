package com.example.biometricsampleapp.biometric

import android.app.Application
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationResult
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class BiometricAuthenticationError(message: String, code: Int) : Exception(message)
class NoPinCodeSavedOnDeviceToAuthenticateWithException(message: String = "No pin code saved on device to authenticate with") : Exception(message)


enum class BiometricAvailabilityStatuses {
    BIOMETRIC_SUCCESS,
    BIOMETRIC_ERROR_NO_HARDWARE,
    BIOMETRIC_ERROR_HW_UNAVAILABLE,
    BIOMETRIC_ERROR_NONE_ENROLLED,
    BIOMETRIC_ERROR_UNSUPPORTED_STATUS,
    ;

    fun getMessage() : String{
        return when(this) {
            BIOMETRIC_SUCCESS -> {
                "App can authenticate using biometrics."
            }
            BIOMETRIC_ERROR_NO_HARDWARE -> {
                "No biometric features available on this device."
            }
            BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                "Biometric features are currently unavailable."
            }
            BIOMETRIC_ERROR_NONE_ENROLLED -> {
                "Biometric features are currently unavailable. But user can enroll."
            }

            BIOMETRIC_ERROR_UNSUPPORTED_STATUS -> {
                "Status returned by framework is not yet in this enum."
            }
        }
    }

    companion object {
        fun getEnumFromCanAuthenticateResponse(response: Int): BiometricAvailabilityStatuses {

            return when (response) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    BIOMETRIC_SUCCESS
                }

                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                    BIOMETRIC_ERROR_NO_HARDWARE
                }

                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    BIOMETRIC_ERROR_HW_UNAVAILABLE
                }

                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    BIOMETRIC_ERROR_NONE_ENROLLED
                }
                else -> {
                    BIOMETRIC_ERROR_UNSUPPORTED_STATUS
                }
            }
        }
    }
}

class BiometricHelper(val application: Application, private val userId: String) {

    // Initialisation du KeyStore et du nom de la clé pour stocker le mot de passe
    // Bien utiliser `AndroidKeyStore` pour stocker les données de manière sécurisée -> https://developer.android.com/training/articles/keystore
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    // Créer une clé par utilisateur
    private val keyNamePrefix = "BiometricSampleAppKey_"

    fun getKeyNameForUser(): String {
        return keyNamePrefix + userId
    }

    fun createBiometricKey() {
        val keyName = getKeyNameForUser()
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            // Oblige l'utilisateur à avoir une authentification sur son appareil (device sans authentification = pas de clé)
            .setUserAuthenticationRequired(true)
            // Oblige à renouveler la clé si l'utilisateur ajoute une nouvelle empreinte digitale à l'appareil
            .setInvalidatedByBiometricEnrollment(true)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    fun removeBiometricKey() {
        val keyName = getKeyNameForUser()
        keyStore.deleteEntry(keyName)
    }

    /**
     * On récupère la clé secrète stockée dans le KeyStore via le keyName défini (1 nom par user / par valeur)
     */
    fun getSecretKey(): SecretKey {
        val keyName = getKeyNameForUser()
        return (keyStore.getEntry(keyName, null) as KeyStore.SecretKeyEntry).secretKey
    }

    fun isBiometricKeyValid(): Boolean {
        return try {
            getSecretKey()
            true
        } catch (e: Exception) {
            false
        }
    }

    fun ensureBiometricKeyAvailable() {
        if (!isBiometricKeyValid()) {
            createBiometricKey()
        }
    }

    fun isBiometricAvailable(): Boolean {
        // Vérifier si le périphérique prend en charge la biométrie
        // https://developer.android.com/training/sign-in/biometric-auth#kotlin
        val biometricManager = BiometricManager.from(application)
        return getBiometricAvailabilityStatuses() == BiometricAvailabilityStatuses.BIOMETRIC_SUCCESS
    }

    fun getBiometricAvailabilityStatuses(): BiometricAvailabilityStatuses {
        return BiometricAvailabilityStatuses.getEnumFromCanAuthenticateResponse(BiometricManager.from(application).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or DEVICE_CREDENTIAL))
    }



    fun getCipher(): Cipher {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
    }

    fun encryptPin(pin: String): String {
        val cipher = getCipher()
        val secretKey = getSecretKey()

        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val encryptedBytes = cipher.doFinal(pin.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(encryptedBytes, android.util.Base64.DEFAULT)
    }

    fun decryptPin(encryptedPin: String, cryptoObject: BiometricPrompt.CryptoObject): String {
        cryptoObject.cipher?.let { cipher ->
            val secretKey = getSecretKey()
            cipher.init(Cipher.DECRYPT_MODE, secretKey)
            val encryptedBytes = Base64.decode(encryptedPin, Base64.DEFAULT)
            val decryptedBytes = cipher.doFinal(encryptedBytes)
            return String(decryptedBytes, Charsets.UTF_8)
        } ?: throw IllegalArgumentException("CryptoObject is null, cannot decrypt pin")
    }


    fun showBiometricPrompt(
        activity: FragmentActivity,
        completion: (Result<Pair<AuthenticationResult, BiometricPrompt.CryptoObject>>) -> Unit
    )  {

        // Face ID ?
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentification biométrique")
            .setSubtitle("Utilisez votre empreinte digitale pour vous connecter")
            .setNegativeButtonText("Annuler")
            .build()

        val biometricPrompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                result.cryptoObject?.let { cryptoObject ->
                    completion(Result.success(Pair(result, cryptoObject)))
                }

            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                completion(Result.failure(BiometricAuthenticationError(errString.toString(), errorCode)))
            }
        })

        val cipher = getCipher()
        val secretKey = getSecretKey()

        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    fun offerBiometricEnrollment(activity: FragmentActivity, pincode: String, completion: (Result<Pair<AuthenticationResult, BiometricPrompt.CryptoObject>>) -> Unit) {

        val cipher = getCipher()
        val secretKey = createBiometricKey()


        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentification biométrique")
            .setSubtitle("Utilisez votre empreinte digitale ou votre visage pour sécuriser votre code PIN")
            .setNegativeButtonText("Annuler")
            .build()

        val biometricPrompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                result.cryptoObject?.let { cryptoObject ->
                    completion(Result.success(Pair(result, cryptoObject)))
                }

            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                completion(Result.failure(BiometricAuthenticationError(errString.toString(), errorCode)))
            }
        })

        biometricPrompt.authenticate(promptInfo)
    }
}
