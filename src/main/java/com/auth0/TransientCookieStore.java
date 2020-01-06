package com.auth0;

import org.apache.commons.lang3.Validate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

/**
 * Allows storage and retrieval/removal of cookies.
 */
class TransientCookieStore {

    private static final int MAX_AGE_SECONDS = 600; // 10 minutes

    // Prevent instantiation
    private TransientCookieStore() {}


    /**
     * Stores a state value as a cookie on the response.
     *
     * @param response the response object to set the cookie on
     * @param state the value for the state cookie. If null, no cookie will be set.
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param useLegacySameSiteCookie whether to set a fallback cookie or not
     */
    static void storeState(HttpServletResponse response, String state, SameSite sameSite, boolean useLegacySameSiteCookie) {
        store(response, StorageUtils.STATE_KEY, state, sameSite, useLegacySameSiteCookie);
    }

    /**
     * Stores a nonce value as a cookie on the response.
     *
     * @param response the response object to set the cookie on
     * @param nonce the value for the nonce cookie. If null, no cookie will be set.
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param useLegacySameSiteCookie whether to set a fallback cookie or not
     */
    static void storeNonce(HttpServletResponse response, String nonce, SameSite sameSite, boolean useLegacySameSiteCookie) {
        store(response, StorageUtils.NONCE_KEY, nonce, sameSite, useLegacySameSiteCookie);
    }

    /**
     * Gets the value associated with the state cookie and removes it.
     *
     * @param request the request object
     * @param response the response object
     * @param useLegacySameSiteCookie whether to use a fallback cookie or not
     * @return the value of the state cookie, if it exists
     */
    static String getState(HttpServletRequest request, HttpServletResponse response, boolean useLegacySameSiteCookie) {
        return getOnce(StorageUtils.STATE_KEY, request, response, useLegacySameSiteCookie);
    }

    /**
     * Gets the value associated with the nonce cookie and removes it.
     * @param request the request object
     * @param response the response object
     * @param useLegacySameSiteCookie whether to use a fallback cookie or not
     * @return the value of the nonce cookie, if it exists
     */
    static String getNonce(HttpServletRequest request, HttpServletResponse response, boolean useLegacySameSiteCookie) {
        return getOnce(StorageUtils.NONCE_KEY, request, response, useLegacySameSiteCookie);
    }

    private static void store(HttpServletResponse response, String key, String value, SameSite sameSite, boolean useLegacySameSiteCookie) {
        Validate.notNull(response, "response must not be null");
        Validate.notNull(key, "key must not be null");
        Validate.notNull(sameSite, "sameSite must not be null");

        if (value == null) {
            return;
        }

        boolean sameSiteNone = SameSite.NONE == sameSite;

        String cookie = String.format("%s=%s; HttpOnly; Max-Age=%d; SameSite=%s", key, value, MAX_AGE_SECONDS, sameSite.getValue());
        if (sameSiteNone) {
            cookie = cookie.concat("; Secure");
        }

        // Servlet Cookie API does not yet support setting the SameSite attribute, so just set cookie on header
        response.addHeader("Set-Cookie", cookie);

        // set legacy fallback cookie (if configured) for clients that won't accept SameSite=None
        if (sameSiteNone && useLegacySameSiteCookie) {
            String legacyCookie = String.format("%s=%s; HttpOnly; Max-Age=%d", "_" + key, value, MAX_AGE_SECONDS);
            response.addHeader("Set-Cookie", legacyCookie);
        }

    }

    private static String getOnce(String cookieName, HttpServletRequest request, HttpServletResponse response, boolean useLegacySameSiteCookie) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        List<Cookie> cookiesList = Arrays.asList(cookies);
        Cookie cookie = null;
        for (Cookie c : cookiesList) {
            if (cookieName.equals(c.getName())) {
                cookie = c;
                break;
            }
        }

        String cookieVal = null;
        if (cookie != null) {
            cookieVal = cookie.getValue();
            delete(cookie, response);
        }

        Cookie legacyCookie = null;
        for (Cookie c : cookiesList) {
            if (("_" + cookieName).equals(c.getName())) {
                legacyCookie = c;
                break;
            }
        }

        String legacyCookieVal = null;
        if (legacyCookie != null) {
            legacyCookieVal = legacyCookie.getValue();
            delete(legacyCookie, response);
        }

        return cookieVal != null ? cookieVal : legacyCookieVal;
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
