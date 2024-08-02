package com.example.biometricsampleapp

import androidx.fragment.app.viewModels
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.example.biometricsampleapp.data.model.LoggedInUser
import com.example.biometricsampleapp.databinding.FragmentHomeScreenBinding

class HomeScreenFragment : Fragment() {


    private val args by navArgs<HomeScreenFragmentArgs>()

    private val viewModel: HomeScreenViewModel by viewModels<HomeScreenViewModel> {
        HomeScreenViewModel.provideFactory(args.LoggedUserInformation)
    }

    private lateinit var binding: FragmentHomeScreenBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)


    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        binding = FragmentHomeScreenBinding.inflate(layoutInflater)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.logoutButton.setOnClickListener {
            viewModel.getDebugInfos()
            //findNavController().popBackStack()
        }

        binding.resetBiometricPromptByDefault.setOnClickListener {
            viewModel.decryptDataTest(requireActivity())
        }

        binding.resetKeyStore.setOnClickListener {
            viewModel.resetKeyStore()
        }

        viewModel.debugInfos.observe(viewLifecycleOwner) { debugInfos ->
            binding.textViewUserInformations.text = debugInfos
        }
    }
}