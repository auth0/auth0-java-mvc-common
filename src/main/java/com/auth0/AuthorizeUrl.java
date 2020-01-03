package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.auth.AuthorizeUrlBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Class to create and customize an Auth0 Authorize URL.
 * It's not reusable.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused", "SameParameterValue"})
public class AuthorizeUrl {

    private static final String SCOPE_OPENID = "openid";

    private HttpServletResponse response;
    private HttpServletRequest request;
    private final AuthorizeUrlBuilder builder;
    private final String responseType;
    private boolean legacySameSiteCookie = true;
    private String nonce;
    private String state;

    private boolean used;

    /**
     * Creates a new instance that can be used to build an Auth0 Authorization URL.
     *
     * Using this constructor with a non-null {@link HttpServletResponse} will store the state and nonce as
     * cookies when the {@link AuthorizeUrl#build()} method is called, with the appropriate SameSite attribute depending
     * on the responseType. State and nonce will also be stored in the {@link javax.servlet.http.HttpSession} as a fallback,
     * but this behavior will be removed in a future release, and only cookies will be used.
     *
     * @param client       the Auth0 Authentication API client
     * @parem request      the HTTP request. Used to store state and nonce as a fallback if cookies not set.
     * @param response     the response where the state and nonce will be stored as cookies
     * @param redirectUrl  the url to redirect to after authentication
     * @param responseType the response type to use
     */
    AuthorizeUrl(AuthAPI client, HttpServletRequest request, HttpServletResponse response, String redirectUrl, String responseType) {
        this.request = request;
        this.response = response;
        this.responseType = responseType;
        this.builder = client.authorizeUrl(redirectUrl)
                .withResponseType(responseType)
                .withScope(SCOPE_OPENID);
    }

    /**
     * Creates a new instance that can be used to build an Auth0 Authorization URL.
     *
     * Using this constructor will store the state and nonce in the {@link javax.servlet.http.HttpSession}, and will be
     * deprecated and removed in the future, in favor of storing the state and nonce in Cookies.
     *
     * @param client       the Auth0 Authentication API client
     * @param request      the request where the state and nonce will be stored in the {@link javax.servlet.http.HttpSession}
     * @param redirectUrl  the url to redirect to after authentication
     * @param responseType the response type to use
     */
    // TODO - deprecate in minor version, remove in next major
    AuthorizeUrl(AuthAPI client, HttpServletRequest request, String redirectUrl, String responseType) {
        this(client, request, null, redirectUrl, responseType);
        this.legacySameSiteCookie = false;
    }

    /**
     * Sets the connection value.
     *
     * @param connection connection to set
     * @return the builder instance
     */
    public AuthorizeUrl withConnection(String connection) {
        builder.withConnection(connection);
        return this;
    }

    /**
     * Sets whether a fallback cookie should be used for clients that do not support "SameSite=None".
     * Only applicable when this instance is created with {@link AuthorizeUrl#AuthorizeUrl(AuthAPI, HttpServletRequest, HttpServletResponse, String, String)}.
     *
     * @param legacySameSiteCookie whether or not to set fallback auth cookies for clients that do not support "SameSite=None"
     * @return the builder instance
     */
    AuthorizeUrl withLegacySameSiteCookie(boolean legacySameSiteCookie) {
        this.legacySameSiteCookie = legacySameSiteCookie;
        return this;
    }

    /**
     * Sets the audience value.
     *
     * @param audience audience to set
     * @return the builder instance
     */
    public AuthorizeUrl withAudience(String audience) {
        builder.withAudience(audience);
        return this;
    }

    /**
     * Sets the state value.
     *
     * @param state state to set
     * @return the builder instance
     */
    public AuthorizeUrl withState(String state) {
        this.state = state;
        builder.withState(state);
        return this;
    }

    /**
     * Sets the nonce value.
     *
     * @param nonce nonce to set
     * @return the builder instance
     */
    public AuthorizeUrl withNonce(String nonce) {
        this.nonce = nonce;
        builder.withParameter("nonce", nonce);
        return this;
    }

    /**
     * Sets the scope value.
     *
     * @param scope scope to set
     * @return the builder instance
     */
    public AuthorizeUrl withScope(String scope) {
        builder.withScope(scope);
        return this;
    }

    /**
     * Sets an additional parameter.
     *
     * @param name  name of the parameter
     * @param value value of the parameter to set
     * @return the builder instance
     */
    public AuthorizeUrl withParameter(String name, String value) {
        if ("state".equals(name) || "nonce".equals(name)) {
            throw new IllegalArgumentException("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.");
        }
        if ("response_type".equals(name)) {
            throw new IllegalArgumentException("Response type cannot be changed once set.");
        }
        if ("redirect_uri".equals(name)) {
            throw new IllegalArgumentException("Redirect URI cannot be changed once set.");
        }
        builder.withParameter(name, value);
        return this;
    }

    /**
     * Creates a string representation of the URL with the configured parameters.
     * It cannot be called more than once.
     *
     * @return the string URL
     * @throws IllegalStateException if it's called more than once
     */
    public String build() throws IllegalStateException {
        if (used) {
            throw new IllegalStateException("The AuthorizeUrl instance must not be reused.");
        }

        if (response != null) {
            TransientCookieStore.SameSite sameSiteValue = containsFormPost() ?
                    TransientCookieStore.SameSite.NONE : TransientCookieStore.SameSite.LAX;


            TransientCookieStore.storeState(response, state, sameSiteValue, legacySameSiteCookie);
            TransientCookieStore.storeNonce(response, nonce, sameSiteValue, legacySameSiteCookie);
        }

        // Also store in Session just in case developer uses deprecated
        // AuthenticationController.handle(HttpServletRequest) API
        RandomStorage.setSessionState(request, state);
        RandomStorage.setSessionNonce(request, nonce);

        used = true;
        return builder.build();
    }

    private boolean containsFormPost() {
        String[] splitResponseTypes = responseType.trim().split("\\s+");
        List<String> responseTypes = Collections.unmodifiableList(Arrays.asList(splitResponseTypes));
        return RequestProcessor.requiresFormPostResponseMode((responseTypes));
    }

}
