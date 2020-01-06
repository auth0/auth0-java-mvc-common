package com.auth0;

import org.apache.commons.lang3.Validate;

/**
 * Represents a cookie to be used for transfer of authentiction-based data such as state and nonce.
 *
 * This is an internal replacement for the Java Servlet Cookie implementation, so that it can set the SameSite
 * attribute (not yet supported in Java Servlet API). It is intended to be used via the Set-Cookie header.
 *
 * By default, cookies will have the HttpOnly attribute set, and a Max-Age of 600 seconds (10 minutes).
 */
class AuthCookie {

    private final static int MAX_AGE_SECONDS = 600; // 10 minutes

    private final String key;
    private final String value;
    private boolean secure;
    private SameSite sameSite;

    /**
     * Create a new instance.
     *
     * Note that keys and values are stored as-is. Clients should encode and decode values as needed.
     *
     * @param key The cookie key
     * @param value The cookie value
     */
    AuthCookie(String key, String value) {
        Validate.notNull(key, "Key must not be null");
        Validate.notNull(value, "Value must not be null");

        this.key = key;
        this.value = value;
    }

    /**
     * Sets whether the Secure attribute should be set on the cookie. False by default.
     *
     * @param secure whether the Cookie should have the Secure attribute or not.
     */
    void setSecure(boolean secure) {
        this.secure = secure;
    }

    /**
     * Sets the value of the SameSite attribute. Unless set, no SameSite attribute will be set on the cookie.
     *
     * @param sameSite The value of the SameSite attribute.
     */
    void setSameSite(SameSite sameSite) {
        this.sameSite = sameSite;
    }

    /**
     * Builds and returns a string representing this cookie instance, to be used as the value of a "Set-Cookie" header.
     *
     * @return the value of this cookie as a string to be used as the value of a "Set-Cookie" header.
     */
    String buildHeaderString() {
        String baseCookieString = String.format("%s=%s; HttpOnly; Max-Age=%d", key, value, MAX_AGE_SECONDS);
        if (sameSite != null) {
            baseCookieString = baseCookieString.concat(String.format("; SameSite=%s", sameSite.getValue()));
        }
        if (secure) {
            baseCookieString = baseCookieString.concat("; Secure");
        }
        return baseCookieString;
    }

}
