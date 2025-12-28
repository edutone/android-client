package io.netbird.client

import android.content.Context
import android.util.Log
import io.netbird.gomobile.android.HandleOAuthCallback
import io.netbird.gomobile.android.HandleOAuthError
import io.netbird.gomobile.android.MobileOAuth
import io.netbird.gomobile.android.MobileOAuthConfig
import io.netbird.gomobile.android.NewMobileOAuth
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.ref.WeakReference

/**
 * SSOBridge provides the Kotlin interface to the Go MobileOAuth layer.
 *
 * This class manages the OAuth PKCE flow for SSO authentication:
 * 1. StartAuthFlow() generates PKCE parameters and returns the authorization URL
 * 2. The app opens the URL in Chrome Custom Tab
 * 3. After authentication, the IdP redirects to sdvpn://oauth/callback
 * 4. OAuthCallbackActivity receives the deep link and calls handleCallback()
 * 5. The callback is validated and code is exchanged for session token
 * 6. Session is stored securely in Android Keystore
 * 7. Auto-refresh keeps session valid while app is active
 */
object SSOBridge {
    private const val TAG = "SSOBridge"

    // Default SSO Bridge configuration
    private const val DEFAULT_REDIRECT_URI = "sdvpn://oauth/callback"
    private const val DEFAULT_SSO_BRIDGE_URL = "https://vpn.schoolday.io"
    private const val DEFAULT_PROVIDER_ID = ""

    // Auto-refresh configuration
    private const val REFRESH_CHECK_INTERVAL_MS = 5 * 60 * 1000L // Check every 5 minutes
    private const val REFRESH_THRESHOLD_MS = 60 * 60 * 1000L // Refresh when < 1 hour to expiry

    private var mobileOAuth: MobileOAuth? = null
    private var secureStore: SecureTokenStore? = null
    private var contextRef: WeakReference<Context>? = null
    private var refreshJob: Job? = null
    private var ssoBridgeUrl: String = DEFAULT_SSO_BRIDGE_URL

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
        fun onAuthSuccess(session: SessionInfo)
        fun onAuthError(errorCode: String, errorDescription: String)
    }

    /**
     * Listener interface for session state changes.
     */
    interface SessionListener {
        fun onSessionRefreshed(session: SessionInfo)
        fun onSessionExpired()
        fun onSessionError(errorCode: String, errorDescription: String)
    }

    /**
     * Legacy listener interface for backwards compatibility.
     */
    interface LegacyOAuthListener {
        fun onAuthSuccess(codeVerifier: String, redirectUri: String)
        fun onAuthError(errorCode: String, errorDescription: String)
    }

    private var listener: OAuthListener? = null
    private var legacyListener: LegacyOAuthListener? = null
    private var sessionListener: SessionListener? = null

    /**
     * Initialize the SSO Bridge with context and configuration.
     *
     * @param context Application context (required for secure storage)
     * @param ssoBridgeUrl The URL of the SSO Bridge server
     * @param redirectUri The OAuth redirect URI (deep link)
     * @param providerId Optional OIDC provider ID
     */
    @JvmStatic
    fun initialize(
        context: Context,
        ssoBridgeUrl: String = DEFAULT_SSO_BRIDGE_URL,
        redirectUri: String = DEFAULT_REDIRECT_URI,
        providerId: String = DEFAULT_PROVIDER_ID
    ) {
        Log.d(TAG, "Initializing SSOBridge with URL: $ssoBridgeUrl")

        contextRef = WeakReference(context.applicationContext)
        this.ssoBridgeUrl = ssoBridgeUrl

        // Initialize secure storage
        secureStore = SecureTokenStore.getInstance(context.applicationContext)

        // Log hardware backing status
        secureStore?.let { store ->
            val isHardwareBacked = store.isHardwareBackedKeystore()
            Log.i(TAG, "Secure storage initialized, hardware-backed: $isHardwareBacked")
        }

        val config = MobileOAuthConfig().apply {
            this.ssoBridgeURL = ssoBridgeUrl
            this.redirectURI = redirectUri
            this.providerID = providerId
        }

        mobileOAuth = NewMobileOAuth(config)
        Log.d(TAG, "SSOBridge initialized successfully")
    }

    /**
     * Initialize with default URL (legacy support).
     */
    @JvmStatic
    fun initialize(
        ssoBridgeUrl: String = DEFAULT_SSO_BRIDGE_URL,
        redirectUri: String = DEFAULT_REDIRECT_URI,
        providerId: String = DEFAULT_PROVIDER_ID
    ) {
        Log.w(TAG, "Initializing SSOBridge without context - secure storage not available")

        this.ssoBridgeUrl = ssoBridgeUrl

        val config = MobileOAuthConfig().apply {
            this.ssoBridgeURL = ssoBridgeUrl
            this.redirectURI = redirectUri
            this.providerID = providerId
        }

        mobileOAuth = NewMobileOAuth(config)
    }

    /**
     * Set a session listener for session state changes.
     */
    @JvmStatic
    fun setSessionListener(listener: SessionListener?) {
        sessionListener = listener
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

        if (mobileOAuth == null) {
            Log.e(TAG, "SSOBridge not initialized")
            listener.onAuthError("not_initialized", "SSOBridge not initialized")
            return null
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
     */
    @JvmStatic
    fun startAuthFlowLegacy(listener: LegacyOAuthListener): String? {
        this.legacyListener = listener
        this.listener = null

        if (mobileOAuth == null) {
            Log.e(TAG, "SSOBridge not initialized")
            listener.onAuthError("not_initialized", "SSOBridge not initialized")
            return null
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
                    roles = emptyList()
                )

                // Store session securely
                storeSessionSecurely(session)

                // Start auto-refresh
                startAutoRefresh()

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
     * Store the session securely using Android Keystore.
     */
    private fun storeSessionSecurely(session: SessionInfo) {
        try {
            secureStore?.storeSession(session)
            Log.d(TAG, "Session stored securely")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store session securely", e)
        }
    }

    /**
     * Get the stored session if valid.
     *
     * @return The stored session, or null if none exists or expired
     */
    @JvmStatic
    fun getStoredSession(): SessionInfo? {
        return try {
            val stored = secureStore?.getSession()
            if (stored != null) {
                SessionInfo(
                    sessionToken = stored.sessionToken,
                    expiresAt = stored.expiresAt.toString(),
                    userId = stored.userId,
                    email = stored.email,
                    name = stored.name,
                    roles = stored.roles
                )
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get stored session", e)
            null
        }
    }

    /**
     * Get the session token if a valid session exists.
     */
    @JvmStatic
    fun getSessionToken(): String? {
        return secureStore?.getSessionToken()
    }

    /**
     * Check if a valid session exists.
     */
    @JvmStatic
    fun hasValidSession(): Boolean {
        return secureStore?.hasValidSession() == true
    }

    /**
     * Check if the session should be refreshed.
     */
    @JvmStatic
    fun shouldRefreshSession(): Boolean {
        return secureStore?.getSession()?.shouldRefresh() == true
    }

    /**
     * Start automatic session refresh.
     * Checks periodically and refreshes when approaching expiry.
     */
    private fun startAutoRefresh() {
        refreshJob?.cancel()
        refreshJob = CoroutineScope(Dispatchers.Default).launch {
            while (true) {
                delay(REFRESH_CHECK_INTERVAL_MS)
                checkAndRefreshSession()
            }
        }
        Log.d(TAG, "Started auto-refresh job")
    }

    /**
     * Stop automatic session refresh.
     */
    @JvmStatic
    fun stopAutoRefresh() {
        refreshJob?.cancel()
        refreshJob = null
        Log.d(TAG, "Stopped auto-refresh job")
    }

    /**
     * Check if refresh is needed and perform it.
     */
    private suspend fun checkAndRefreshSession() {
        val stored = secureStore?.getSession() ?: return

        if (stored.isExpired()) {
            Log.d(TAG, "Session has expired")
            withContext(Dispatchers.Main) {
                sessionListener?.onSessionExpired()
            }
            clearSession()
            return
        }

        if (stored.shouldRefresh()) {
            Log.d(TAG, "Session needs refresh")
            refreshSession()
        }
    }

    /**
     * Refresh the current session.
     */
    suspend fun refreshSession() {
        // TODO: Implement session refresh via SSO Bridge API
        // For now, just update the last refresh timestamp
        withContext(Dispatchers.IO) {
            try {
                secureStore?.updateLastRefresh()
                Log.d(TAG, "Session refresh timestamp updated")

                // Notify listener
                val stored = secureStore?.getSession()
                if (stored != null) {
                    val session = SessionInfo(
                        sessionToken = stored.sessionToken,
                        expiresAt = stored.expiresAt.toString(),
                        userId = stored.userId,
                        email = stored.email,
                        name = stored.name,
                        roles = stored.roles
                    )
                    withContext(Dispatchers.Main) {
                        sessionListener?.onSessionRefreshed(session)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Session refresh failed", e)
                withContext(Dispatchers.Main) {
                    sessionListener?.onSessionError("refresh_failed", e.message ?: "Unknown error")
                }
            }
        }
    }

    /**
     * Resume session on app resume.
     * Call this from Activity.onResume().
     */
    @JvmStatic
    fun onAppResume() {
        Log.d(TAG, "App resumed, checking session")
        CoroutineScope(Dispatchers.Default).launch {
            checkAndRefreshSession()
        }

        // Restart auto-refresh if we have a valid session
        if (hasValidSession() && refreshJob?.isActive != true) {
            startAutoRefresh()
        }
    }

    /**
     * Pause session refresh on app pause.
     * Call this from Activity.onPause().
     */
    @JvmStatic
    fun onAppPause() {
        Log.d(TAG, "App paused, stopping auto-refresh")
        stopAutoRefresh()
    }

    /**
     * Exchange authorization code for session token (suspend function).
     */
    suspend fun exchangeCodeForSession(code: String, state: String): SessionInfo? {
        return withContext(Dispatchers.IO) {
            try {
                val tokenResponse = mobileOAuth?.exchangeCodeSimple(code, state)
                if (tokenResponse != null) {
                    val session = SessionInfo(
                        sessionToken = tokenResponse.sessionToken,
                        expiresAt = tokenResponse.expiresAt,
                        userId = tokenResponse.userID,
                        email = tokenResponse.email,
                        name = tokenResponse.name,
                        roles = emptyList()
                    )
                    storeSessionSecurely(session)
                    session
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
     */
    @JvmStatic
    fun handleError(errorCode: String, errorDescription: String) {
        Log.e(TAG, "OAuth error: $errorCode - $errorDescription")
        HandleOAuthError(errorCode, errorDescription)
        listener?.onAuthError(errorCode, errorDescription)
        legacyListener?.onAuthError(errorCode, errorDescription)
    }

    /**
     * Clear the stored session (logout).
     */
    @JvmStatic
    fun clearSession() {
        Log.d(TAG, "Clearing session")
        stopAutoRefresh()
        secureStore?.clearSession()
        listener = null
        legacyListener = null
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
    }

    /**
     * Complete logout: clear session and cancel any flows.
     */
    @JvmStatic
    fun logout() {
        Log.d(TAG, "Logging out")
        cancelFlow()
        clearSession()
    }

    /**
     * Check if an OAuth flow is in progress.
     */
    @JvmStatic
    fun isFlowInProgress(): Boolean {
        return listener != null || legacyListener != null
    }

    /**
     * Check if secure storage is hardware-backed.
     */
    @JvmStatic
    fun isSecureStorageHardwareBacked(): Boolean {
        return secureStore?.isHardwareBackedKeystore() == true
    }
}
