package com.auth0;

import javax.servlet.http.HttpServletRequest;

import static com.auth0.QueryParamUtils.*;


/**
 * Convenience Utils methods for manipulating the nonce key/value pair held in state param
 * Used for CSRF protection - should always be sent with login request
 * <p>
 * We assign on login, and remove on successful callback completion
 * callback request is checked for validity by correctly matching state in http request
 * with state held in storage (library uses http session)
 * <p>
 * By using a nonce attribute in the state request param, we can also add additional attributes
 * as needed such as externalRedirectURL for SSO scenarios etc
 */
public class NonceUtils {

    public static final String NONCE_KEY = "nonce";


    /**
     * Add a nonce value to session storage if not already exists
     * Will be appended as a key / value pair to the state attribute
     * whose value is of the form of a query param (key1=value1&amp;key2=value2)
     * @param req the http servlet request
     */
    public static void addNonceToStorage(final HttpServletRequest req) {
        final String stateFromStorage = SessionUtils.getState(req) != null ? SessionUtils.getState(req) : "";
        // only add if no existing entry..
        if (!keyInQueryParams(stateFromStorage, NONCE_KEY)) {
            final String updatedState = addOrReplaceInQueryParams(stateFromStorage, NONCE_KEY, NonceFactory.create());
            SessionUtils.setState(req, updatedState);
        }
    }

    /**
     * Remove a nonce value from session storage if present
     * The key / value pair will be removed from the state attribute
     * @param req the http servlet request
     */
    public static void removeNonceFromStorage(final HttpServletRequest req) {
        final String stateFromStorage = SessionUtils.getState(req) != null ? SessionUtils.getState(req) : "";
        final String stateFromStorageWithoutNonce = removeFromQueryParams(stateFromStorage, NONCE_KEY);
        SessionUtils.setState(req, stateFromStorageWithoutNonce);
    }

    /**
     * Indicates whether the nonce value in the http request matches the nonce value in session storage
     * @param req the http servlet request
     * @param stateFromRequest the state value received with the http request
     * @return boolean indicating whether the nonce received in the request matches session storage value
     */
    public static boolean matchesNonceInStorage(final HttpServletRequest req, final String stateFromRequest) {
        final String nonceFromRequest = parseFromQueryParams(stateFromRequest, NONCE_KEY);
        final String stateFromStorage = SessionUtils.getState(req);
        final String nonceFromStorage = parseFromQueryParams(stateFromStorage, NONCE_KEY);
        return nonceFromRequest != null && !nonceFromRequest.isEmpty() && nonceFromRequest.equals(nonceFromStorage);
    }

}
