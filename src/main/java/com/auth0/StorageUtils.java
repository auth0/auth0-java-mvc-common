package com.auth0;

import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;

class StorageUtils {

    private StorageUtils() {}

    static final String STATE_KEY = "com.auth0.state";
    static final String NONCE_KEY = "com.auth0.nonce";

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
