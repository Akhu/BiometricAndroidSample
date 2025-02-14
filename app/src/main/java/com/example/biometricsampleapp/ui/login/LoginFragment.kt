package com.example.biometricsampleapp.ui.login

import android.app.Activity
import android.content.Intent
import android.os.Build
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProvider
import androidx.annotation.StringRes
import androidx.fragment.app.Fragment
import android.os.Bundle
import android.provider.Settings
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AlertDialog
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.core.widget.doAfterTextChanged
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.example.biometricsampleapp.databinding.FragmentLoginBinding

import com.example.biometricsampleapp.R
import com.example.biometricsampleapp.biometric.BiometricAvailabilityStatuses
import com.example.biometricsampleapp.biometric.BiometricAvailabilityStatuses.*
import com.example.biometricsampleapp.biometric.BiometricHelper
import com.example.biometricsampleapp.biometric.CouldNotEnrollForBiometricException
import com.example.biometricsampleapp.biometric.NoPinCodeSavedOnDeviceToAuthenticateWithException
import com.example.biometricsampleapp.data.model.LoggedInUser
import com.google.android.material.snackbar.Snackbar
import kotlin.math.log

class LoginFragment : Fragment() {

    private val loginViewModel: LoginViewModel by viewModels<LoginViewModel> {
        LoginViewModel.Factory
    }

    private var _binding: FragmentLoginBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    val launchSettings = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        loginViewModel.checkBiometricSystemStatus()
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentLoginBinding.inflate(inflater, container, false)
        return binding.root

    }

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val passwordEditText = binding.pincode
        val loginButton = binding.login
        val loadingProgressBar = binding.loading

        val userIdEditText = binding.userIdEditText

        binding.debugInfo.text = loginViewModel.getDebugInfos()

        loginViewModel.loginFormState.observe(viewLifecycleOwner,
            Observer { loginFormState ->
                if (loginFormState == null) {
                    return@Observer
                }
                loginButton.isEnabled = loginFormState.isDataValid
                loginFormState.passwordError?.let {
                    passwordEditText.error = getString(it)
                }
            })

        loginViewModel.getUiState().observe(viewLifecycleOwner) { state ->
            when(state) {
                is LoginUIState.Attempted -> {
                    binding.loading.visibility = View.GONE
                    state.result.onSuccess { data ->
                        // Go to HomeScreen
                        if(state.shouldEnrollForBiometrics) {
                            offerBiometricEnrollment()
                            return@onSuccess
                        }
                        // If not biometry enabled, show biometry setup screen
                        updateUiWithUser(data)
                    }

                    state.result.onFailure { failure ->

                        when(failure) {
                            is NoPinCodeSavedOnDeviceToAuthenticateWithException -> {
                                Snackbar.make(
                                    view,
                                    "Aucun code PIN n'est enregistré sur l'appareil pour l'authentification",
                                    Snackbar.LENGTH_LONG
                                ).show()
                            }

                            is CouldNotEnrollForBiometricException -> {
                                updateUiWithUser(failure.loggedInUser)
                            }

                            is KeyPermanentlyInvalidatedException -> {
                                Log.e("Biometric", "Key invalidated")
                                Snackbar.make(
                                    view,
                                    "La clé d'authentification biométrie à été révoquée (il y a surement eu une modification des paramètres de sécurité de l'appareil)",
                                    Snackbar.LENGTH_LONG
                                ).show()
                                loginViewModel.removeBiometricDataForUser()
                                binding.debugInfo.text = loginViewModel.getDebugInfos()
                            }
                            else -> {
                                Log.e("Biometric", "Error while trying to authenticate with biometric", failure)
                                loginViewModel.removeBiometricDataForUser()
                            }
                        }
                    }

                }
                LoginUIState.Idle -> {
                    // Hide loading
                    binding.loading.visibility = View.GONE
                }
                LoginUIState.Loading -> {
                    // Show loading
                    binding.loading.visibility = View.VISIBLE
                }
            }
        }

        val afterTextChangedListener = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {
                // ignore
            }

            override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {
                // ignore
            }

            override fun afterTextChanged(s: Editable) {
                loginViewModel.loginDataChanged(
                    passwordEditText.text.toString()
                )
            }
        }
        userIdEditText.text = Editable.Factory.getInstance().newEditable("1")
        userIdEditText.doAfterTextChanged {
            loginViewModel.changeUserToConnect(it.toString())
        }

        passwordEditText.addTextChangedListener(afterTextChangedListener)
        passwordEditText.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                loginViewModel.login(
                    passwordEditText.text.toString()
                )
            }
            false
        }

        loginButton.setOnClickListener {
            loadingProgressBar.visibility = View.VISIBLE
            loginViewModel.login(
                passwordEditText.text.toString()
            )
        }

        view.post {

                loginViewModel.getCanTriggerBiometricPrompt().observe(viewLifecycleOwner) { canTriggerBiometricPrompt ->
                        Log.d("Biometric Status checked", "Can trigger biometric prompt: $canTriggerBiometricPrompt")
                        if (canTriggerBiometricPrompt) {
                            loginViewModel.loginWithBiometric(requireActivity())
                        }
                    }
                loginViewModel.getBiometricAvailable()
                    .observe(viewLifecycleOwner) { biometricAvailable ->
                        when (biometricAvailable) {
                            BIOMETRIC_ERROR_NONE_ENROLLED -> {
                                // Prompts the user to create credentials that your app accepts.
                                val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                        putExtra(
                                            Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                                            BIOMETRIC_STRONG or DEVICE_CREDENTIAL
                                        )
                                    }
                                }
                                launchSettings.launch(enrollIntent)
                            }

                            else -> {
                                Log.d("Biometric Status checked", biometricAvailable.getMessage())
                            }
                        }
                    }
        }
    }

    private fun updateUiWithUser(model: LoggedInUser) {
        val welcome = getString(R.string.welcome) + model.displayName
        // TODO : initiate successful logged in experience
        val appContext = context?.applicationContext ?: return
        Toast.makeText(appContext, welcome, Toast.LENGTH_LONG).show()

        val action = LoginFragmentDirections.actionLoginFragmentToHomeScreenFragment(model)
        findNavController().navigate(action)
    }

    private fun showLoginFailed(@StringRes errorString: Int) {
        val appContext = context?.applicationContext ?: return
        Toast.makeText(appContext, errorString, Toast.LENGTH_LONG).show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private fun offerBiometricEnrollment() {
        AlertDialog.Builder(requireActivity())
            .setTitle("Activer l'authentification biométrique ?")
            .setMessage("Voulez-vous utiliser votre empreinte digitale ou la reconnaissance faciale pour vous connecter plus rapidement la prochaine fois ?")
            .setPositiveButton("Activer" ) { _, _ ->
                loginViewModel.enrollForBiometric(requireActivity())
            }
            .setNegativeButton("Pas maintenant") { _, _ ->
                loginViewModel.removeBiometricDataForUser()
            }
            .show()
    }
}