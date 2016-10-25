package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Holds conveniences for HTTP Session retrieval and creation,
 * and conveniences for setting and getting the session attributes
 * used in the Auth0 MVC libraries
 */
public class SessionUtils {

    public static final String STATE = "state";
    public static final String TOKENS = "tokens";
    public static final String AUTH0_USER = "auth0User";

    /**
     * Get current session or create one if it does not already exist
     *
     * @param req the http servlet request
     * @return the HTTP Session
     */
    protected static HttpSession getSession(final HttpServletRequest req) {
        return req.getSession(true);
    }

    /**
     * Returns the object bound with the state attribute in this session, or
     * <code>null</code> if no object is bound to state
     *
     * @param req the http servlet request
     * @return the state attribute value associated with the current session
     */
    public static String getState(final HttpServletRequest req) {
        return (String) getSession(req).getAttribute(STATE);
    }

    /**
     * Binds the state object to this session
     * If a state object is already bound to the session,
     * the object is replaced.
     *
     * @param req the http servlet request
     * @param state the state attribute to bind to this session
     */
    public static void setState(final HttpServletRequest req, final String state) {
        getSession(req).setAttribute(STATE, state);
    }

    /**
     * Returns the object bound with the tokens attribute in this session, or
     * <code>null</code> if no object is bound to tokens
     *
     * @param req the http servlet request
     * @return the tokens attribute value associated with the current session
     */
    public static Tokens getTokens(final HttpServletRequest req) {
        return (Tokens) getSession(req).getAttribute(TOKENS);
    }

    /**
     * Binds the tokens object to this session
     * If a tokens object is already bound to the session,
     * the object is replaced.
     *
     * @param req the http servlet request
     * @param tokens the tokens attribute to bind to this session
     */
    public static void setTokens(final HttpServletRequest req, final Tokens tokens) {
        getSession(req).setAttribute(TOKENS, tokens);
    }

    /**
     * Returns the object bound with the auth0user attribute in this session, or
     * <code>null</code> if no object is bound to auth0user
     *
     * @param req the http servlet request
     * @return the auth0user attribute value associated with the current session
     */
    public static Auth0User getAuth0User(final HttpServletRequest req) {
        return (Auth0User) getSession(req).getAttribute(AUTH0_USER);
    }

    /**
     * Binds the auth0user object to this session
     * If an auth0user object is already bound to the session,
     * the object is replaced.
     *
     * @param req the http servlet request
     * @param auth0User the auth0user attribute to bind to this session
     */
    public static void setAuth0User(final HttpServletRequest req, final Auth0User auth0User) {
        getSession(req).setAttribute(AUTH0_USER, auth0User);
    }

}
