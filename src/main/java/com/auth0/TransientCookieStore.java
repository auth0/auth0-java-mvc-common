package com.auth0;

import org.apache.commons.lang3.Validate;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Allows storage and retrieval/removal of transient cookies used during the OAuth transaction.
 *
 * <p>Each login transaction gets its own uniquely-named cookies (keyed by state value),
 * preventing multi-tab race conditions where concurrent logins would overwrite each other's state.</p>
 */
class TransientCookieStore {

    // Prevent instantiation
    private TransientCookieStore() {}


    /**
     * Stores a state value as a transaction-keyed cookie on the response.
     * The cookie name includes the state value itself, ensuring each login flow
     * gets its own isolated cookie (e.g., "com.auth0.state.{state_value}").
     *
     * @param response the response object to set the cookie on
     * @param state the value for the state cookie. If null, no cookie will be set.
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param useLegacySameSiteCookie whether to set a fallback cookie or not
     * @param isSecureCookie whether to always set the Secure cookie attribute or not
     * @param cookiePath the path for the cookie
     */
    static void storeState(HttpServletResponse response, String state, SameSite sameSite, boolean useLegacySameSiteCookie, boolean isSecureCookie, String cookiePath) {
        if (state == null) {
            return;
        }
        store(response, StorageUtils.transactionStateKey(state), state, sameSite, useLegacySameSiteCookie, isSecureCookie, cookiePath);
    }

    /**
     * Stores a nonce value as a transaction-keyed cookie on the response.
     * The cookie is keyed by the state value (not the nonce), so it can be
     * retrieved during callback using the state parameter from the URL.
     *
     * @param response the response object to set the cookie on
     * @param nonce the value for the nonce cookie. If null, no cookie will be set.
     * @param state the state value for this transaction (used as key in cookie name)
     * @param sameSite the value for the SameSite attribute on the cookie
     * @param useLegacySameSiteCookie whether to set a fallback cookie or not
     * @param isSecureCookie whether to always set the Secure cookie attribute or not
     * @param cookiePath the path for the cookie
     */
    static void storeNonce(HttpServletResponse response, String nonce, String state, SameSite sameSite, boolean useLegacySameSiteCookie, boolean isSecureCookie, String cookiePath) {
        if (nonce == null || state == null) {
            return;
        }
        store(response, StorageUtils.transactionNonceKey(state), nonce, sameSite, useLegacySameSiteCookie, isSecureCookie, cookiePath);
    }

    /**
     * Gets the value associated with the state cookie for this transaction and removes it.
     * Uses the state parameter from the callback request to look up the correct transaction cookie.
     * Falls back to the legacy fixed-name cookie for backward compatibility during rolling upgrades.
     *
     * @param request the request object
     * @param response the response object
     * @return the value of the state cookie, if it exists
     */
    static String getState(HttpServletRequest request, HttpServletResponse response) {
        String stateParam = request.getParameter("state");
        if (stateParam == null) {
            return null;
        }

        // Try transaction-keyed cookie first (new behavior)
        String value = getOnce(StorageUtils.transactionStateKey(stateParam), request, response);
        if (value != null) {
            return value;
        }

        // Fallback: legacy fixed-name cookie (for in-flight transactions during upgrade from v1)
        return getOnce(StorageUtils.STATE_KEY, request, response);
    }

    /**
     * Gets the value associated with the nonce cookie for this transaction and removes it.
     * Uses the state parameter to look up the correct transaction-keyed nonce cookie.
     * Falls back to the legacy fixed-name cookie for backward compatibility.
     *
     * @param request the request object
     * @param response the response object
     * @param state the state value from the callback (used to find the correct nonce cookie)
     * @return the value of the nonce cookie, if it exists
     */
    static String getNonce(HttpServletRequest request, HttpServletResponse response, String state) {
        if (state == null) {
            return null;
        }

        // Try transaction-keyed cookie first (new behavior)
        String value = getOnce(StorageUtils.transactionNonceKey(state), request, response);
        if (value != null) {
            return value;
        }

        // Fallback: legacy fixed-name cookie (for in-flight transactions during upgrade from v1)
        return getOnce(StorageUtils.NONCE_KEY, request, response);
    }

    /**
     * Stores the origin domain as an HMAC-signed cookie, bound to the state parameter.
     * The HMAC is computed over both the domain and the state, ensuring the cookie
     * cannot be replayed across different transactions.
     *
     * @param response  the response to set the cookie on
     * @param domain    the resolved Auth0 domain
     * @param state     the state parameter for this transaction (used as HMAC binding context)
     * @param sameSite  the SameSite attribute value
     * @param path      the cookie path, or null
     * @param isSecure  whether to set the Secure attribute
     * @param secret    the client secret used for HMAC signing
     */
    static void storeSignedOriginDomain(HttpServletResponse response, String domain, String state,
            SameSite sameSite, String path, boolean isSecure, String secret) {
        String signedDomain = SignedCookieUtils.sign(domain, state, secret);
        store(response, StorageUtils.ORIGIN_DOMAIN_KEY, signedDomain, sameSite, true, isSecure, path);
    }

    /**
     * Retrieves and verifies the HMAC-signed origin domain cookie, checking that
     * the HMAC was computed with the given state (transaction binding).
     *
     * @param request  the request to read the cookie from
     * @param response the response used to delete the cookie after reading
     * @param state    the state parameter from this callback request
     * @param secret   the client secret used for HMAC verification
     * @return the verified domain value, or {@code null} if the cookie is missing,
     *         the signature is invalid, or the state doesn't match (replay attempt)
     */
    static String getSignedOriginDomain(HttpServletRequest request, HttpServletResponse response,
            String state, String secret) {
        String signedValue = getOnce(StorageUtils.ORIGIN_DOMAIN_KEY, request, response);
        if (signedValue == null) {
            return null;
        }
        return SignedCookieUtils.verifyAndExtract(signedValue, state, secret);
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
