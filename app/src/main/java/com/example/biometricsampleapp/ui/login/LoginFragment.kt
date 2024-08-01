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
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.example.biometricsampleapp.databinding.FragmentLoginBinding

import com.example.biometricsampleapp.R
import com.example.biometricsampleapp.biometric.BiometricAvailabilityStatuses
import com.example.biometricsampleapp.biometric.BiometricAvailabilityStatuses.*
import com.example.biometricsampleapp.biometric.BiometricHelper
import com.example.biometricsampleapp.data.model.LoggedInUser

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
                        }
                        // If not biometry enabled, show biometry setup screen
                        updateUiWithUser(data)
                    }

                    state.result.onFailure {
                        // Show error message
                        showLoginFailed(R.string.login_failed)
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

            loginViewModel.getCanTriggerBiometricPrompt()
                .observe(viewLifecycleOwner) { canTriggerBiometricPrompt ->
                    if (canTriggerBiometricPrompt) {
                        loginViewModel.loginWithBiometric(requireActivity())
                    }
                }
            loginViewModel.getBiometricAvailable()
                .observe(viewLifecycleOwner) { biometricAvailable ->
                    when(biometricAvailable) {
                        BIOMETRIC_ERROR_NONE_ENROLLED -> {
                            // Prompts the user to create credentials that your app accepts.
                            val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                    putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
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

        findNavController().navigate(R.id.action_loginFragment_to_homeScreenFragment)
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
            .setPositiveButton("Activer", null)
            .setNegativeButton("Pas maintenant") { _, _ ->
                //loginViewModel.removeBiometricDataForUser()
            }
            .show()
    }
}