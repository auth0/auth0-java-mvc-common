package com.auth0;

import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;

class StorageUtils {

    private StorageUtils() {}

    static final String STATE_KEY = "com.auth0.state";
    static final String NONCE_KEY = "com.auth0.nonce";
    static final String ORIGIN_DOMAIN_KEY = "com.auth0.origin_domain";

    /**
     * Max-Age for transaction cookies in seconds (10 minutes).
     * Orphaned cookies from abandoned login flows will auto-expire.
     */
    static final int TRANSACTION_COOKIE_MAX_AGE = 600;

    /**
     * Constructs a transaction-keyed state cookie name.
     * Each login transaction gets its own cookie, preventing multi-tab overwrites.
     *
     * @param state the state value for this transaction
     * @return the cookie name in the form "com.auth0.state.{state}"
     */
    static String transactionStateKey(String state) {
        return STATE_KEY + "." + state;
    }

    /**
     * Constructs a transaction-keyed nonce cookie name.
     *
     * @param state the state value for this transaction (used as key, not the nonce itself)
     * @return the cookie name in the form "com.auth0.nonce.{state}"
     */
    static String transactionNonceKey(String state) {
        return NONCE_KEY + "." + state;
    }

    /**
     * Generates a new random string using {@link SecureRandom}.
     * The output can be used as State or Nonce values for API requests.
     *
     * @return a new random string.
     */
    static String secureRandomString() {
        final SecureRandom sr = new SecureRandom();
        final byte[] randomBytes = new byte[32];
        sr.nextBytes(randomBytes);
        return Base64.encodeBase64URLSafeString(randomBytes);
    }
}
