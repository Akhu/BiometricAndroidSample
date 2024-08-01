package com.example.biometricsampleapp.biometric

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecurePreferences(context: Context, userId: String) {
    private val encryptedPinPrefix = "encrypted_pin_"

    private var encryptedPinPrefKeyForUser = encryptedPinPrefix + userId + "_globule"

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val encryptedSharedPreferences = EncryptedSharedPreferences.create(
        context,
        "SecurePrefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveEncryptedPin(encryptedPin: String) {
        encryptedSharedPreferences.edit().putString(encryptedPinPrefKeyForUser, encryptedPin).apply()
    }

    fun getEncryptedPin(): String? {
        return encryptedSharedPreferences.getString(encryptedPinPrefKeyForUser, null)
    }

    fun clearEncryptedPin() {
        encryptedSharedPreferences.edit().remove(encryptedPinPrefKeyForUser).apply()
    }

    fun hasEncryptedPin(): Boolean {
        return encryptedSharedPreferences.contains(encryptedPinPrefKeyForUser)
    }

}