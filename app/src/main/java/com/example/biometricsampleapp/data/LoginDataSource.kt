package com.example.biometricsampleapp.data

import com.example.biometricsampleapp.data.model.LoggedInUser
import java.io.IOException

/**
 * Class that handles authentication w/ login credentials and retrieves user information.
 */
class LoginDataSource {

    fun login(username: String, password: String): Result<LoggedInUser> {
        try {
            // TODO: handle loggedInUser authentication
            val fakeUser = LoggedInUser(java.util.UUID.randomUUID().toString(), "Jane Doe")
            return Result.success(fakeUser)
        } catch (e: Throwable) {
            return Result.failure(IOException("Error logging in", e))
        }
    }

    fun loginWithPincode(pincode: String, userId: String): Result<LoggedInUser> {
        try {
            // TODO: handle loggedInUser authentication
            if (pincode == "5555") {
                val fakeUser = LoggedInUser(userId, "Jane Doe")
                return Result.success(fakeUser)
            } else {
                return Result.failure(IOException("Wrong Pincode"))
            }
        } catch (e: Throwable) {
            return Result.failure(IOException("Error logging in", e))
        }
    }

    fun logout() {
        // TODO: revoke authentication
    }
}