package com.auth0;

import org.apache.commons.lang3.Validate;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Helper class to handle easy session key-value storage.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public abstract class SessionUtils {

    /**
     * Extracts the HttpSession from the given request.
     *
     * @param req a valid request to get the session from
     * @return the session of the request
     */
    protected static HttpSession getSession(HttpServletRequest req) {
        return req.getSession(true);
    }

    /**
     * Set's the attribute value to the request session.
     *
     * @param req   a valid request to get the session from
     * @param name  the name of the attribute
     * @param value the value to set
     */
    public static void set(HttpServletRequest req, String name, Object value) {
        Validate.notNull(req);
        Validate.notNull(name);
        getSession(req).setAttribute(name, value);
    }

    /**
     * Get the attribute with the given name from the request session.
     *
     * @param req  a valid request to get the session from
     * @param name the name of the attribute
     * @return the attribute stored in the session or null if it doesn't exists
     */
    public static Object get(HttpServletRequest req, String name) {
        Validate.notNull(req);
        Validate.notNull(name);
        return getSession(req).getAttribute(name);
    }

    /**
     * Same as {@link #get(HttpServletRequest, String)} but it also removes the value from the request session.
     *
     * @param req  a valid request to get the session from
     * @param name the name of the attribute
     * @return the attribute stored in the session or null if it doesn't exists
     */
    public static Object remove(HttpServletRequest req, String name) {
        Validate.notNull(req);
        Validate.notNull(name);
        Object value = get(req, name);
        getSession(req).removeAttribute(name);
        return value;
    }
}
