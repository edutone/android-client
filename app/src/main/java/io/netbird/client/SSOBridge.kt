package io.netbird.client

import android.util.Log
import io.netbird.gomobile.android.HandleOAuthCallback
import io.netbird.gomobile.android.HandleOAuthError
import io.netbird.gomobile.android.MobileOAuth
import io.netbird.gomobile.android.MobileOAuthConfig
import io.netbird.gomobile.android.MobileTokenResponse
import io.netbird.gomobile.android.NewMobileOAuth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * SSOBridge provides the Kotlin interface to the Go MobileOAuth layer.
 *
 * This class manages the OAuth PKCE flow for SSO authentication:
 * 1. StartAuthFlow() generates PKCE parameters and returns the authorization URL
 * 2. The app opens the URL in Chrome Custom Tab
 * 3. After authentication, the IdP redirects to sdvpn://oauth/callback
 * 4. OAuthCallbackActivity receives the deep link and calls handleCallback()
 * 5. The callback is validated and code is exchanged for session token
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
     * Session information returned after successful authentication.
     */
    data class SessionInfo(
        val sessionToken: String,
        val expiresAt: String,
        val userId: String,
        val email: String,
        val name: String,
        val roles: List<String>
    )

    /**
     * Listener interface for OAuth flow results.
     */
    interface OAuthListener {
        /**
         * Called when authentication is successful and session is obtained.
         */
        fun onAuthSuccess(session: SessionInfo)

        /**
         * Called when authentication fails.
         */
        fun onAuthError(errorCode: String, errorDescription: String)
    }

    /**
     * Legacy listener interface for backwards compatibility.
     * Use OAuthListener for full session support.
     */
    interface LegacyOAuthListener {
        fun onAuthSuccess(codeVerifier: String, redirectUri: String)
        fun onAuthError(errorCode: String, errorDescription: String)
    }

    private var listener: OAuthListener? = null
    private var legacyListener: LegacyOAuthListener? = null

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
     * Start the OAuth PKCE flow with full session support.
     *
     * @param listener Callback for auth result with session info
     * @return The authorization URL to open in the browser, or null on error
     */
    @JvmStatic
    fun startAuthFlow(listener: OAuthListener): String? {
        this.listener = listener
        this.legacyListener = null

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
     * Start the OAuth PKCE flow (legacy version).
     *
     * @param listener Callback for auth result (legacy)
     * @return The authorization URL to open in the browser, or null on error
     */
    @JvmStatic
    fun startAuthFlowLegacy(listener: LegacyOAuthListener): String? {
        this.legacyListener = listener
        this.listener = null

        val oauth = mobileOAuth
        if (oauth == null) {
            Log.e(TAG, "SSOBridge not initialized, initializing with defaults")
            initialize()
        }

        return try {
            val authUrl = mobileOAuth?.startAuthFlowSimple()
            Log.d(TAG, "Started OAuth flow (legacy), auth URL: ${authUrl?.take(50)}...")
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
     * This method validates the callback and exchanges the code for a session token.
     *
     * @param code The authorization code from the IdP
     * @param state The OAuth state parameter for CSRF protection
     * @return true if the callback was handled successfully
     */
    @JvmStatic
    fun handleCallback(code: String, state: String): Boolean {
        Log.d(TAG, "Handling OAuth callback - code length: ${code.length}, state: ${state.take(8)}...")

        return try {
            // For legacy flow, just validate and return
            if (legacyListener != null) {
                val oauthState = HandleOAuthCallback(code, state)
                if (oauthState != null) {
                    Log.d(TAG, "OAuth callback validated successfully (legacy)")
                    legacyListener?.onAuthSuccess(
                        oauthState.codeVerifier,
                        oauthState.redirectURI
                    )
                    return true
                } else {
                    Log.e(TAG, "OAuth callback returned null state")
                    legacyListener?.onAuthError("invalid_state", "OAuth state validation failed")
                    return false
                }
            }

            // For full flow, exchange code for session token
            val tokenResponse = mobileOAuth?.exchangeCodeSimple(code, state)

            if (tokenResponse != null) {
                Log.d(TAG, "Token exchange successful for: ${tokenResponse.email}")
                val session = SessionInfo(
                    sessionToken = tokenResponse.sessionToken,
                    expiresAt = tokenResponse.expiresAt,
                    userId = tokenResponse.userID,
                    email = tokenResponse.email,
                    name = tokenResponse.name,
                    roles = emptyList() // Go slice to Kotlin list not directly supported
                )
                listener?.onAuthSuccess(session)
                true
            } else {
                Log.e(TAG, "Token exchange returned null")
                listener?.onAuthError("token_exchange_failed", "Failed to exchange code for session")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "OAuth callback/token exchange failed", e)
            listener?.onAuthError("callback_failed", e.message ?: "Unknown error")
            legacyListener?.onAuthError("callback_failed", e.message ?: "Unknown error")
            false
        }
    }

    /**
     * Exchange authorization code for session token (suspend function for coroutines).
     *
     * @param code The authorization code from the IdP
     * @param state The OAuth state parameter
     * @return SessionInfo on success, null on failure
     */
    suspend fun exchangeCodeForSession(code: String, state: String): SessionInfo? {
        return withContext(Dispatchers.IO) {
            try {
                val tokenResponse = mobileOAuth?.exchangeCodeSimple(code, state)
                if (tokenResponse != null) {
                    SessionInfo(
                        sessionToken = tokenResponse.sessionToken,
                        expiresAt = tokenResponse.expiresAt,
                        userId = tokenResponse.userID,
                        email = tokenResponse.email,
                        name = tokenResponse.name,
                        roles = emptyList()
                    )
                } else {
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Token exchange failed", e)
                null
            }
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
        legacyListener?.onAuthError(errorCode, errorDescription)
    }

    /**
     * Cancel the current OAuth flow.
     */
    @JvmStatic
    fun cancelFlow() {
        Log.d(TAG, "Cancelling OAuth flow")
        mobileOAuth?.clearAllFlows()
        listener = null
        legacyListener = null
        currentState = null
    }

    /**
     * Check if an OAuth flow is in progress.
     */
    @JvmStatic
    fun isFlowInProgress(): Boolean {
        return listener != null || legacyListener != null
    }

    /**
     * Get the current session token if available.
     * For VPN connection, this token should be used for authentication.
     */
    @JvmStatic
    fun getSessionToken(): String? {
        // This would be stored after successful authentication
        // For now, the session is returned via the listener
        return null
    }
}
