package com.auth0;

import org.apache.commons.lang3.Validate;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Allows storage and retrieval/removal of cookies.
 */
class TransientCookieStore {

    // Prevent instantiation
    private TransientCookieStore() {}


    /**
     * Stores a state value as a cookie on the response.
     *
     * @param response the response object to set the cookie on
     * @param state the value for the state cookie. If null, no cookie will be set.
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param useLegacySameSiteCookie whether to set a fallback cookie or not
     * @param isSecureCookie whether to always set the Secure cookie attribute or not
     */
    static void storeState(HttpServletResponse response, String state, SameSite sameSite, boolean useLegacySameSiteCookie, boolean isSecureCookie, String cookiePath) {
        store(response, StorageUtils.STATE_KEY, state, sameSite, useLegacySameSiteCookie, isSecureCookie, cookiePath);
    }

    /**
     * Stores a nonce value as a cookie on the response.
     *
     * @param response the response object to set the cookie on
     * @param nonce the value for the nonce cookie. If null, no cookie will be set.
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param useLegacySameSiteCookie whether to set a fallback cookie or not
     * @param isSecureCookie whether to always set the Secure cookie attribute or not
     */
    static void storeNonce(HttpServletResponse response, String nonce, SameSite sameSite, boolean useLegacySameSiteCookie, boolean isSecureCookie, String cookiePath) {
        store(response, StorageUtils.NONCE_KEY, nonce, sameSite, useLegacySameSiteCookie, isSecureCookie, cookiePath);
    }

    /**
     * Gets the value associated with the state cookie and removes it.
     *
     * @param request the request object
     * @param response the response object
     * @return the value of the state cookie, if it exists
     */
    static String getState(HttpServletRequest request, HttpServletResponse response) {
        return getOnce(StorageUtils.STATE_KEY, request, response);
    }

    /**
     * Gets the value associated with the nonce cookie and removes it.
     *
     * @param request the request object
     * @param response the response object
     * @return the value of the nonce cookie, if it exists
     */
    static String getNonce(HttpServletRequest request, HttpServletResponse response) {
        return getOnce(StorageUtils.NONCE_KEY, request, response);
    }

    private static void store(HttpServletResponse response, String key, String value, SameSite sameSite, boolean useLegacySameSiteCookie, boolean isSecureCookie, String cookiePath) {
        Validate.notNull(response, "response must not be null");
        Validate.notNull(key, "key must not be null");
        Validate.notNull(sameSite, "sameSite must not be null");

        if (value == null) {
            return;
        }

        boolean isSameSiteNone = SameSite.NONE == sameSite;

        AuthCookie sameSiteCookie = new AuthCookie(key, value);
        sameSiteCookie.setSameSite(sameSite);
        sameSiteCookie.setSecure(isSameSiteNone || isSecureCookie);
        if (cookiePath != null) {
            sameSiteCookie.setPath(cookiePath);
        }

        // Servlet Cookie API does not yet support setting the SameSite attribute, so just set cookie on header
        response.addHeader("Set-Cookie", sameSiteCookie.buildHeaderString());

        // set legacy fallback cookie (if configured) for clients that won't accept SameSite=None
        if (isSameSiteNone && useLegacySameSiteCookie) {
            AuthCookie legacyCookie = new AuthCookie("_" + key, value);
            legacyCookie.setSecure(isSecureCookie);
            response.addHeader("Set-Cookie", legacyCookie.buildHeaderString());
        }

    }

    private static String getOnce(String cookieName, HttpServletRequest request, HttpServletResponse response) {
        Cookie[] requestCookies = request.getCookies();
        if (requestCookies == null) {
            return null;
        }

        Cookie foundCookie = null;
        for (Cookie c : requestCookies) {
            if (cookieName.equals(c.getName())) {
                foundCookie = c;
                break;
            }
        }

        String foundCookieVal = null;
        if (foundCookie != null) {
            foundCookieVal = decode(foundCookie.getValue());
            delete(foundCookie, response);
        }

        Cookie foundLegacyCookie = null;
        for (Cookie c : requestCookies) {
            if (("_" + cookieName).equals(c.getName())) {
                foundLegacyCookie = c;
                break;
            }
        }

        String foundLegacyCookieVal = null;
        if (foundLegacyCookie != null) {
            foundLegacyCookieVal = decode(foundLegacyCookie.getValue());
            delete(foundLegacyCookie, response);
        }

        return foundCookieVal != null ? foundCookieVal : foundLegacyCookieVal;
    }

    private static void delete(Cookie cookie, HttpServletResponse response) {
        cookie.setMaxAge(0);
        cookie.setValue("");
        response.addCookie(cookie);
    }

    private static String decode(String valueToDecode) {
        try {
            return URLDecoder.decode(valueToDecode, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new AssertionError("UTF-8 character set not supported", e.getCause());
        }
    }
}
