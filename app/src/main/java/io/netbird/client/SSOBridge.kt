package io.netbird.client

import android.util.Log
import io.netbird.gomobile.android.HandleOAuthCallback
import io.netbird.gomobile.android.HandleOAuthError
import io.netbird.gomobile.android.MobileOAuth
import io.netbird.gomobile.android.MobileOAuthConfig
import io.netbird.gomobile.android.NewMobileOAuth

/**
 * SSOBridge provides the Kotlin interface to the Go MobileOAuth layer.
 *
 * This class manages the OAuth PKCE flow for SSO authentication:
 * 1. StartAuthFlow() generates PKCE parameters and returns the authorization URL
 * 2. The app opens the URL in Chrome Custom Tab
 * 3. After authentication, the IdP redirects to sdvpn://oauth/callback
 * 4. OAuthCallbackActivity receives the deep link and calls handleCallback()
 * 5. The callback is processed in Go and tokens are obtained
 */
object SSOBridge {
    private const val TAG = "SSOBridge"

    // Default SSO Bridge configuration
    // These can be overridden by the app configuration
    private const val DEFAULT_REDIRECT_URI = "sdvpn://oauth/callback"
    private const val DEFAULT_SSO_BRIDGE_URL = "https://vpn.schoolday.io"
    private const val DEFAULT_PROVIDER_ID = "" // Use default provider

    private var mobileOAuth: MobileOAuth? = null
    private var currentState: String? = null

    /**
     * Listener interface for OAuth flow results.
     */
    interface OAuthListener {
        fun onAuthSuccess(codeVerifier: String, redirectUri: String)
        fun onAuthError(errorCode: String, errorDescription: String)
    }

    private var listener: OAuthListener? = null

    /**
     * Initialize the SSO Bridge with custom configuration.
     *
     * @param ssoBridgeUrl The URL of the SSO Bridge server
     * @param redirectUri The OAuth redirect URI (deep link)
     * @param providerId Optional OIDC provider ID
     */
    @JvmStatic
    fun initialize(
        ssoBridgeUrl: String = DEFAULT_SSO_BRIDGE_URL,
        redirectUri: String = DEFAULT_REDIRECT_URI,
        providerId: String = DEFAULT_PROVIDER_ID
    ) {
        Log.d(TAG, "Initializing SSOBridge with URL: $ssoBridgeUrl")

        val config = MobileOAuthConfig().apply {
            this.ssoBridgeURL = ssoBridgeUrl
            this.redirectURI = redirectUri
            this.providerID = providerId
        }

        mobileOAuth = NewMobileOAuth(config)
        Log.d(TAG, "SSOBridge initialized successfully")
    }

    /**
     * Start the OAuth PKCE flow.
     *
     * @param listener Callback for auth result
     * @return The authorization URL to open in the browser, or null on error
     */
    @JvmStatic
    fun startAuthFlow(listener: OAuthListener): String? {
        this.listener = listener

        val oauth = mobileOAuth
        if (oauth == null) {
            Log.e(TAG, "SSOBridge not initialized, initializing with defaults")
            initialize()
        }

        return try {
            val authUrl = mobileOAuth?.startAuthFlowSimple()
            Log.d(TAG, "Started OAuth flow, auth URL: ${authUrl?.take(50)}...")
            authUrl
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start auth flow", e)
            listener.onAuthError("start_failed", e.message ?: "Unknown error")
            null
        }
    }

    /**
     * Handle an OAuth callback from a deep link.
     * Called by OAuthCallbackActivity when it receives the callback.
     *
     * @param code The authorization code from the IdP
     * @param state The OAuth state parameter for CSRF protection
     * @return true if the callback was handled successfully
     */
    @JvmStatic
    fun handleCallback(code: String, state: String): Boolean {
        Log.d(TAG, "Handling OAuth callback - code length: ${code.length}, state: ${state.take(8)}...")

        return try {
            val oauthState = HandleOAuthCallback(code, state)

            if (oauthState != null) {
                Log.d(TAG, "OAuth callback validated successfully")
                listener?.onAuthSuccess(
                    oauthState.codeVerifier,
                    oauthState.redirectURI
                )
                true
            } else {
                Log.e(TAG, "OAuth callback returned null state")
                listener?.onAuthError("invalid_state", "OAuth state validation failed")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "OAuth callback failed", e)
            listener?.onAuthError("callback_failed", e.message ?: "Unknown error")
            false
        }
    }

    /**
     * Handle an OAuth error from a deep link.
     * Called by OAuthCallbackActivity when the IdP returns an error.
     *
     * @param errorCode The OAuth error code
     * @param errorDescription Human-readable error description
     */
    @JvmStatic
    fun handleError(errorCode: String, errorDescription: String) {
        Log.e(TAG, "OAuth error: $errorCode - $errorDescription")
        HandleOAuthError(errorCode, errorDescription)
        listener?.onAuthError(errorCode, errorDescription)
    }

    /**
     * Cancel the current OAuth flow.
     */
    @JvmStatic
    fun cancelFlow() {
        Log.d(TAG, "Cancelling OAuth flow")
        mobileOAuth?.clearAllFlows()
        listener = null
        currentState = null
    }

    /**
     * Check if an OAuth flow is in progress.
     */
    @JvmStatic
    fun isFlowInProgress(): Boolean {
        return listener != null
    }
}
