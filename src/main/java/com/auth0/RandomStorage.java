package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

class RandomStorage extends SessionUtils {

    /**
     * Check's if the request {@link HttpSession} saved state is equal to the given state.
     * After the check, the value will be removed from the session.
     *
     * @param req   the request
     * @param state the state value to compare against.
     * @return whether the state matches the expected one or not.
     */
    static boolean checkSessionState(HttpServletRequest req, String state) {
        String currentState = (String) remove(req, StorageUtils.STATE_KEY);
        if (currentState == null) {
            return state == null;
        } else {
            return currentState.equals(state);
        }
    }

    /**
     * Saves the given state in the request {@link HttpSession}.
     * If a state is already bound to the session, the value is replaced.
     *
     * @param req   the request.
     * @param state the state value to set.
     */
    static void setSessionState(HttpServletRequest req, String state) {
        set(req, StorageUtils.STATE_KEY, state);
    }

    /**
     * Saves the given nonce in the request {@link HttpSession}.
     * If a nonce is already bound to the session, the value is replaced.
     *
     * @param req   the request.
     * @param nonce the nonce value to set.
     */
    static void setSessionNonce(HttpServletRequest req, String nonce) {
        set(req, StorageUtils.NONCE_KEY, nonce);
    }

    /**
     * Removes the nonce present in the request {@link HttpSession} and then returns it.
     *
     * @param req the HTTP Servlet request.
     * @return the nonce value or null if it was not set.
     */
    static String removeSessionNonce(HttpServletRequest req) {
        return (String) remove(req, StorageUtils.NONCE_KEY);
    }
}