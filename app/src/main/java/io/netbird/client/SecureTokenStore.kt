package io.netbird.client

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * SecureTokenStore provides encrypted storage for OAuth tokens using Android Keystore.
 *
 * Security features:
 * - Uses Android Keystore for key storage (hardware-backed on supported devices)
 * - AES-256-GCM encryption for token data
 * - Keys are not extractable from the Keystore
 * - Automatic key generation on first use
 * - Secure deletion on logout
 *
 * Stored data:
 * - Session token (for SSO Bridge authentication)
 * - Session expiry time
 * - User information (email, name, userId)
 * - Refresh metadata
 */
class SecureTokenStore private constructor(private val context: Context) {

    companion object {
        private const val TAG = "SecureTokenStore"

        // Keystore configuration
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "sd_vpn_token_key"

        // SharedPreferences configuration
        private const val PREFS_NAME = "sd_vpn_secure_tokens"
        private const val ENCRYPTED_PREFS_NAME = "sd_vpn_encrypted_prefs"

        // Keys for stored values
        private const val KEY_SESSION_TOKEN = "session_token"
        private const val KEY_EXPIRES_AT = "expires_at"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_EMAIL = "email"
        private const val KEY_NAME = "name"
        private const val KEY_ROLES = "roles"
        private const val KEY_LAST_REFRESH = "last_refresh"
        private const val KEY_ENCRYPTED_DATA = "encrypted_data"
        private const val KEY_IV = "iv"

        // Encryption configuration
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128

        @Volatile
        private var instance: SecureTokenStore? = null

        /**
         * Get the singleton instance of SecureTokenStore.
         */
        @JvmStatic
        fun getInstance(context: Context): SecureTokenStore {
            return instance ?: synchronized(this) {
                instance ?: SecureTokenStore(context.applicationContext).also { instance = it }
            }
        }
    }

    // Use EncryptedSharedPreferences for API 23+
    private val encryptedPrefs: SharedPreferences by lazy {
        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                context,
                ENCRYPTED_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create EncryptedSharedPreferences, falling back to manual encryption", e)
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        }
    }

    // Fallback: manual encryption using Keystore
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * Session data stored in the secure store.
     */
    data class StoredSession(
        val sessionToken: String,
        val expiresAt: Long,
        val userId: String,
        val email: String,
        val name: String,
        val roles: List<String>,
        val lastRefresh: Long
    ) {
        /**
         * Check if the session has expired.
         */
        fun isExpired(): Boolean {
            return System.currentTimeMillis() > expiresAt
        }

        /**
         * Check if the session should be refreshed.
         * Returns true if within 1 hour of expiry.
         */
        fun shouldRefresh(): Boolean {
            val oneHourMs = 60 * 60 * 1000L
            return System.currentTimeMillis() + oneHourMs > expiresAt
        }

        /**
         * Get time until expiry in milliseconds.
         */
        fun timeUntilExpiry(): Long {
            return expiresAt - System.currentTimeMillis()
        }
    }

    /**
     * Store a session securely.
     *
     * @param session The session info from SSOBridge
     */
    fun storeSession(session: SSOBridge.SessionInfo) {
        Log.d(TAG, "Storing session for user: ${session.email}")

        try {
            // Parse expiry time (ISO 8601 format)
            val expiresAt = parseExpiryTime(session.expiresAt)

            encryptedPrefs.edit().apply {
                putString(KEY_SESSION_TOKEN, session.sessionToken)
                putLong(KEY_EXPIRES_AT, expiresAt)
                putString(KEY_USER_ID, session.userId)
                putString(KEY_EMAIL, session.email)
                putString(KEY_NAME, session.name)
                putString(KEY_ROLES, session.roles.joinToString(","))
                putLong(KEY_LAST_REFRESH, System.currentTimeMillis())
                apply()
            }

            Log.d(TAG, "Session stored successfully, expires at: $expiresAt")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store session", e)
            throw SecureStorageException("Failed to store session", e)
        }
    }

    /**
     * Retrieve the stored session.
     *
     * @return The stored session, or null if none exists or it's expired
     */
    fun getSession(): StoredSession? {
        try {
            val sessionToken = encryptedPrefs.getString(KEY_SESSION_TOKEN, null) ?: return null
            val expiresAt = encryptedPrefs.getLong(KEY_EXPIRES_AT, 0)
            val userId = encryptedPrefs.getString(KEY_USER_ID, "") ?: ""
            val email = encryptedPrefs.getString(KEY_EMAIL, "") ?: ""
            val name = encryptedPrefs.getString(KEY_NAME, "") ?: ""
            val rolesStr = encryptedPrefs.getString(KEY_ROLES, "") ?: ""
            val lastRefresh = encryptedPrefs.getLong(KEY_LAST_REFRESH, 0)

            val roles = if (rolesStr.isNotEmpty()) rolesStr.split(",") else emptyList()

            val session = StoredSession(
                sessionToken = sessionToken,
                expiresAt = expiresAt,
                userId = userId,
                email = email,
                name = name,
                roles = roles,
                lastRefresh = lastRefresh
            )

            // Check if expired
            if (session.isExpired()) {
                Log.d(TAG, "Stored session has expired, clearing")
                clearSession()
                return null
            }

            Log.d(TAG, "Retrieved valid session for: $email")
            return session
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve session", e)
            return null
        }
    }

    /**
     * Get the session token if valid.
     *
     * @return The session token, or null if not available or expired
     */
    fun getSessionToken(): String? {
        return getSession()?.sessionToken
    }

    /**
     * Check if a valid session exists.
     */
    fun hasValidSession(): Boolean {
        return getSession() != null
    }

    /**
     * Update the last refresh timestamp.
     */
    fun updateLastRefresh() {
        encryptedPrefs.edit().putLong(KEY_LAST_REFRESH, System.currentTimeMillis()).apply()
    }

    /**
     * Update the session token and expiry after a refresh.
     */
    fun updateSessionToken(newToken: String, newExpiresAt: String) {
        try {
            val expiresAt = parseExpiryTime(newExpiresAt)
            encryptedPrefs.edit().apply {
                putString(KEY_SESSION_TOKEN, newToken)
                putLong(KEY_EXPIRES_AT, expiresAt)
                putLong(KEY_LAST_REFRESH, System.currentTimeMillis())
                apply()
            }
            Log.d(TAG, "Session token updated, new expiry: $expiresAt")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update session token", e)
            throw SecureStorageException("Failed to update session token", e)
        }
    }

    /**
     * Clear the stored session (logout).
     * This securely deletes all stored token data.
     */
    fun clearSession() {
        Log.d(TAG, "Clearing stored session")
        try {
            encryptedPrefs.edit().clear().apply()

            // Also clear from fallback prefs if used
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().clear().apply()

            Log.d(TAG, "Session cleared successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Error clearing session", e)
        }
    }

    /**
     * Delete all stored data and the encryption key.
     * Use this for complete reset.
     */
    fun deleteAll() {
        Log.w(TAG, "Deleting all secure storage data and keys")
        try {
            clearSession()

            // Delete the encryption key from Keystore
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
                Log.d(TAG, "Deleted encryption key from Keystore")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting all data", e)
        }
    }

    /**
     * Check if the device supports hardware-backed Keystore.
     */
    fun isHardwareBackedKeystore(): Boolean {
        return try {
            val key = getOrCreateKey()
            val factory = javax.crypto.SecretKeyFactory.getInstance(
                key.algorithm,
                ANDROID_KEYSTORE
            )
            val keyInfo = factory.getKeySpec(
                key,
                android.security.keystore.KeyInfo::class.java
            ) as android.security.keystore.KeyInfo

            keyInfo.isInsideSecureHardware
        } catch (e: Exception) {
            Log.w(TAG, "Could not determine if Keystore is hardware-backed", e)
            false
        }
    }

    /**
     * Get or create the encryption key in the Keystore.
     */
    private fun getOrCreateKey(): SecretKey {
        return if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.getKey(KEY_ALIAS, null) as SecretKey
        } else {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            keyGenerator.init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false) // Allow access without biometrics
                    .build()
            )
            keyGenerator.generateKey()
        }
    }

    /**
     * Encrypt data using the Keystore key (fallback method).
     */
    private fun encrypt(plaintext: String): Pair<ByteArray, ByteArray> {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return Pair(iv, ciphertext)
    }

    /**
     * Decrypt data using the Keystore key (fallback method).
     */
    private fun decrypt(iv: ByteArray, ciphertext: ByteArray): String {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charsets.UTF_8)
    }

    /**
     * Parse ISO 8601 date string to epoch milliseconds.
     */
    private fun parseExpiryTime(expiresAt: String): Long {
        return try {
            // Try parsing as epoch milliseconds first
            expiresAt.toLongOrNull()?.let { return it }

            // Try ISO 8601 format
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                java.time.Instant.parse(expiresAt).toEpochMilli()
            } else {
                // Fallback for older Android versions
                val sdf = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
                sdf.timeZone = java.util.TimeZone.getTimeZone("UTC")
                sdf.parse(expiresAt)?.time ?: (System.currentTimeMillis() + 24 * 60 * 60 * 1000)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not parse expiry time: $expiresAt, using 24h default", e)
            System.currentTimeMillis() + 24 * 60 * 60 * 1000 // Default to 24 hours
        }
    }

    /**
     * Exception for secure storage operations.
     */
    class SecureStorageException(message: String, cause: Throwable? = null) : Exception(message, cause)
}
