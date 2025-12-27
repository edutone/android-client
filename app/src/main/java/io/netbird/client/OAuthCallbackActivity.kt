package io.netbird.client

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity

/**
 * Activity that handles OAuth callback deep links.
 *
 * This activity is triggered when the IdP redirects back to the app after authentication:
 * - sdvpn://oauth/callback?code=...&state=...
 * - https://vpn.schoolday.io/oauth/callback?code=...&state=...
 *
 * It extracts the authorization code and state, validates them via SSOBridge,
 * then passes the results to MainActivity for VPN connection.
 */
class OAuthCallbackActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "OAuthCallbackActivity"

        // Intent extras for passing OAuth data to MainActivity
        const val EXTRA_OAUTH_CODE = "oauth_code"
        const val EXTRA_OAUTH_STATE = "oauth_state"
        const val EXTRA_OAUTH_CODE_VERIFIER = "oauth_code_verifier"
        const val EXTRA_OAUTH_REDIRECT_URI = "oauth_redirect_uri"
        const val EXTRA_OAUTH_ERROR = "oauth_error"
        const val EXTRA_OAUTH_ERROR_DESCRIPTION = "oauth_error_description"

        // Action for OAuth callback intent
        const val ACTION_OAUTH_CALLBACK = "io.netbird.client.ACTION_OAUTH_CALLBACK"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val data: Uri? = intent?.data

        if (data == null) {
            Log.e(TAG, "No data URI in intent")
            finishWithError("no_data", "No callback data received")
            return
        }

        Log.d(TAG, "Received OAuth callback: ${data.scheme}://${data.host}${data.path}")

        // Check for OAuth error response
        val error = data.getQueryParameter("error")
        if (error != null) {
            val errorDescription = data.getQueryParameter("error_description") ?: "Unknown error"
            Log.e(TAG, "OAuth error: $error - $errorDescription")
            SSOBridge.handleError(error, errorDescription)
            finishWithError(error, errorDescription)
            return
        }

        // Extract authorization code and state
        val code = data.getQueryParameter("code")
        val state = data.getQueryParameter("state")

        if (code.isNullOrEmpty()) {
            Log.e(TAG, "Missing authorization code in callback")
            finishWithError("missing_code", "Authorization code not found in callback")
            return
        }

        if (state.isNullOrEmpty()) {
            Log.w(TAG, "Missing state parameter (CSRF protection may be compromised)")
            finishWithError("missing_state", "State parameter not found in callback")
            return
        }

        Log.d(TAG, "OAuth callback received - code length: ${code.length}, state: ${state.take(8)}...")

        // Validate the callback through SSOBridge (which validates state via Go)
        val success = SSOBridge.handleCallback(code, state)

        if (!success) {
            Log.e(TAG, "OAuth callback validation failed")
            finishWithError("validation_failed", "OAuth state validation failed")
            return
        }

        Log.d(TAG, "OAuth callback validated successfully")

        // Pass the OAuth data to MainActivity for token exchange
        val mainIntent = Intent(this, MainActivity::class.java).apply {
            action = ACTION_OAUTH_CALLBACK
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(EXTRA_OAUTH_CODE, code)
            putExtra(EXTRA_OAUTH_STATE, state)
        }

        startActivity(mainIntent)
        finish()
    }

    private fun finishWithError(error: String, description: String) {
        val mainIntent = Intent(this, MainActivity::class.java).apply {
            action = ACTION_OAUTH_CALLBACK
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(EXTRA_OAUTH_ERROR, error)
            putExtra(EXTRA_OAUTH_ERROR_DESCRIPTION, description)
        }

        startActivity(mainIntent)
        finish()
    }
}
