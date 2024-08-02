package com.example.biometricsampleapp.biometric

import android.app.Application
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationResult
import androidx.fragment.app.FragmentActivity
import com.example.biometricsampleapp.data.model.LoggedInUser
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class BiometricAuthenticationError(message: String, code: Int) : Exception(message)
class NoPinCodeSavedOnDeviceToAuthenticateWithException(message: String = "No pin code saved on device to authenticate with") : Exception(message)
class CouldNotEnrollForBiometricException(message: String = "Could not enroll for biometric authentication", val loggedInUser: LoggedInUser) : Exception(message)

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

    // Todo: Gérer les exceptions : https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException

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
    private fun getSecretKey(): SecretKey? {
        val keyName = getKeyNameForUser()
        return (keyStore.getKey(keyName, null) as SecretKey)
    }

    fun hasSecretKey() : Boolean {
        val keyName = getKeyNameForUser()
        return keyStore.containsAlias(keyName)
    }

    fun isBiometricKeyValid(who: String): Boolean {
        return try {
            Log.d("BiometricHelper", "Trying to get secret key from $who")
            getSecretKey()
            true
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.d("BiometricHelper", "Key is invalid")
            false
        } catch (e: Exception) {
            Log.d("BiometricHelper", "Exception, ${e.message.toString()}")
            false
        }
    }

    fun ensureBiometricKeyAvailable() {
        if (!isBiometricKeyValid("ensureBiometricKeyAvailable")) {
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

    fun authenticatedEncryptPin(pin: String, authenticatedCipher: Cipher): String {
        val iv = authenticatedCipher.iv

        val encryptedBytes = authenticatedCipher.doFinal(pin.toByteArray(Charsets.UTF_8))
        val combined = iv + encryptedBytes
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    fun authenticatedDecryptPin(encryptedPin: ByteArray, authenticatedCipher: Cipher): String {
        val decryptedBytes = authenticatedCipher.doFinal(encryptedPin)
        return String(decryptedBytes, Charsets.UTF_8)
    }

    fun decryptePincodeBiometricPrompt(
        activity: FragmentActivity,
        encryptedPin: String,
        completion: (Result<String>) -> Unit
    ) {
        val (cipher, encryptedBytes) = preparePinForDecryption(encryptedPin)

        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentification biométrique")
            .setSubtitle("Utilisez votre empreinte digitale pour afficher votre code pin")
            .setNegativeButtonText("Annuler")
            .build()

        val biometricPrompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                result.cryptoObject?.let { cryptoObject ->
                    val authenticatedDecryptedPin = authenticatedDecryptPin(encryptedBytes, cipher)
                    completion(Result.success(authenticatedDecryptedPin))
                }

            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                completion(Result.failure(BiometricAuthenticationError(errString.toString(), errorCode)))
            }
        })



        biometricPrompt.authenticate(promptInfo, cryptoObject)

    }


    fun showBiometricPrompt(
        activity: FragmentActivity,
        encryptedPin: String,
        completion: (Result<Pair<String, BiometricPrompt.CryptoObject>>) -> Unit
    )  {
        val (cipher, encryptedBytes) = preparePinForDecryption(encryptedPin)

        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        // Face ID ?
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentification biométrique")
            .setSubtitle("Utilisez votre empreinte digitale pour vous connecter")
            .setNegativeButtonText("Annuler")
            .build()

        val biometricPrompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                result.cryptoObject?.let { cryptoObject ->
                    val authenticatedDecryptedPin = authenticatedDecryptPin(encryptedBytes, cipher)
                    completion(Result.success(Pair(authenticatedDecryptedPin, cryptoObject)))
                }

            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                completion(Result.failure(BiometricAuthenticationError(errString.toString(), errorCode)))
            }
        })



        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    private fun preparePinForDecryption(encryptedPin: String): Pair<Cipher, ByteArray> {
        val cipher = getCipher()
        val secretKey = getSecretKey()

        val combined = Base64.decode(encryptedPin, Base64.DEFAULT)
        val iv = combined.slice(0 until 16).toByteArray()
        val encryptedBytes = combined.slice(16 until combined.size).toByteArray()

        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
        return Pair(cipher, encryptedBytes)
    }

    fun offerBiometricEnrollment(activity: FragmentActivity, pincode: String, completion: (Result<Pair<String, BiometricPrompt.CryptoObject>>) -> Unit) {

        val cipher = prepareCipherForEncryption()

        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentification biométrique")
            .setSubtitle("Utilisez votre empreinte digitale ou votre visage pour sécuriser votre code PIN")
            .setNegativeButtonText("Annuler")
            .build()

        val biometricPrompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                result.cryptoObject?.let { cryptoObject ->
                    val encryptedPin = authenticatedEncryptPin(pincode, cipher)
                    completion(Result.success(Pair(encryptedPin, cryptoObject)))
                }

            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                completion(Result.failure(BiometricAuthenticationError(errString.toString(), errorCode)))
            }
        })

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    private fun prepareCipherForEncryption(): Cipher {
        val cipher = getCipher()
        if (hasSecretKey()) {
            removeBiometricKey()
            createBiometricKey()
        } else {
            createBiometricKey()
        }
        val secretKey = getSecretKey()
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }
}
