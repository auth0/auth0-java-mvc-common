package com.auth0;

import org.apache.commons.lang3.Validate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Allows storage and retrieval/removal of cookies.
 */
class TransientCookieStore {

    private static final String STATE = "com.auth0.state";
    private static final String NONCE = "com.auth0.nonce";
    private static final int MAX_AGE_SECONDS = 600; // 10 minutes

    // Prevent instantiation
    private TransientCookieStore() {
        throw new UnsupportedOperationException("Creating an instance of TransientCookieStore is not supported");
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
        return new String(Base64.getUrlEncoder().encode(randomBytes));
    }


    /**
     * Stores a state value as a cookie on the response.
     * @param response the response object to set the cookie on
     * @param state the value for the state cookie
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param legacySameSiteCookie whether to set a fallback cookie or not
     */
    static void storeState(HttpServletResponse response, String state, SameSite sameSite, boolean legacySameSiteCookie) {
        store(response, STATE, state, sameSite, legacySameSiteCookie);
    }

    /**
     * Stores a nonce value as a cookie on the response.
     * @param response the response object to set the cookie on
     * @param nonce the value for the nonce cookie
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param legacySameSiteCookie whether to set a fallback cookie or not
     */
    static void storeNonce(HttpServletResponse response, String nonce, SameSite sameSite, boolean legacySameSiteCookie) {
        store(response, NONCE, nonce, sameSite, legacySameSiteCookie);
    }

    /**
     * Gets the value associated with the state cookie and removes that cookie.
     * @param request the request object
     * @param response the response object
     * @param legacySameSiteCookie whether to use a fallback cookie or not
     * @return an {@code Optional} containing the value of the state cookie,
     * or an empty {@code Optional} if the cookie was not found.
     */
    static Optional<String> getState(HttpServletRequest request, HttpServletResponse response, boolean legacySameSiteCookie) {
        return getOnce(STATE, request, response, legacySameSiteCookie);
    }

    /**
     * Gets the value associated with the nonce cookie and removes that cookie.
     * @param request the request object
     * @param response the response object
     * @param legacySameSiteCookie whether to use a fallback cookie or not
     * @return an {@code Optional} containing the value of the nonce cookie,
     * or an empty {@code Optional} if the cookie was not found.
     */
    static Optional<String> getNonce(HttpServletRequest request, HttpServletResponse response, boolean legacySameSiteCookie) {
        return getOnce(NONCE, request, response, legacySameSiteCookie);
    }

    private static void store(HttpServletResponse response, String key, String value, SameSite sameSite, boolean legacySameSiteCookie) {
        Validate.notNull(response, "response must not be null");
        Validate.notNull(key, "key must not be null");
        Validate.notNull(value, "value must not be null");
        Validate.notNull(sameSite, "sameSite must not be null");

        boolean sameSiteNone = SameSite.NONE == sameSite;

        String cookie = String.format("%s=%s; HttpOnly; Max-Age=%d; SameSite=%s", key, value, MAX_AGE_SECONDS, sameSite.getValue());
        if (sameSiteNone) {
            cookie = cookie.concat("; Secure");
        }

        // Servlet Cookie API does not yet support setting the SameSite attribute, so just set cookie on header
        response.addHeader("Set-Cookie", cookie);

        // set legacy fallback cookie (if configured) for clients that won't accept SameSite=None
        if (sameSiteNone && legacySameSiteCookie) {
            String legacyCookie = String.format("%s=%s; HttpOnly; Max-Age=%d", "_" + key, value, MAX_AGE_SECONDS);
            response.addHeader("Set-Cookie", legacyCookie);
        }

    }

    private static Optional<String> getOnce(String cookieName, HttpServletRequest request, HttpServletResponse response, boolean legacySameSiteCookie) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }

        List<Cookie> cookiesList = Arrays.asList(cookies);

        Optional<Cookie> cookie = cookiesList.stream()
                .filter(c -> cookieName.equals(c.getName()))
                .findFirst();

        Optional<String> cookieVal = cookie.map(Cookie::getValue);
        cookie.ifPresent(c -> delete(c, response));

        Optional<String> legacyCookieVal = Optional.empty();
        if (legacySameSiteCookie) {
            Optional<Cookie> legacyCookie = cookiesList.stream()
                    .filter(c -> ("_" + cookieName).equals(c.getName()))
                    .findFirst();

            legacyCookieVal = legacyCookie.map(Cookie::getValue);
            legacyCookie.ifPresent(c -> delete(c, response));
        }

        return cookieVal.isPresent() ? cookieVal : legacyCookieVal;
    }

    private static void delete(Cookie cookie, HttpServletResponse response) {
        cookie.setMaxAge(0);
        cookie.setValue("");
        response.addCookie(cookie);
    }

    enum SameSite {
        LAX("Lax"),
        NONE("None"),
        STRICT("Strict");

        private String value;

        public String getValue() {
            return this.value;
        }

        SameSite(String value) {
            this.value = value;
        }
    }
}
