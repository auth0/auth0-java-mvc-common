package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.auth.AuthorizeUrlBuilder;

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
    private final HttpServletResponse response;
    private final AuthorizeUrlBuilder builder;
    private final String responseType;
    private boolean legacySameSiteCookie;
    private String nonce;
    private String state;

    private boolean used;

    /**
     * @param client       the Auth0 Authentication API client
     * @param response     the response where the state and nonce will be stored as cookies
     * @param redirectUrl  the url to redirect to after authentication
     * @param responseType the response type to use
     */
    AuthorizeUrl(AuthAPI client, HttpServletResponse response, String redirectUrl, String responseType) {
        this.response = response;
        this.responseType = responseType;
        this.legacySameSiteCookie = true;
        this.builder = client.authorizeUrl(redirectUrl)
                .withResponseType(responseType)
                .withScope(SCOPE_OPENID);
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
     * Sets whether a fallback cookie should be used for clients that do not support "SameSite=None"
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

        TransientCookieStore.SameSite sameSiteValue = containsFormPost() ?
                TransientCookieStore.SameSite.NONE : TransientCookieStore.SameSite.LAX;

        if (state != null) {
            TransientCookieStore.storeState(response, state, sameSiteValue, legacySameSiteCookie);
        }

        if (nonce != null) {
            TransientCookieStore.storeNonce(response, nonce, sameSiteValue, legacySameSiteCookie);
        }

        used = true;
        return builder.build();
    }

    private boolean containsFormPost() {
        String[] splitResponseTypes = responseType.trim().split(" ");
        List<String> responseTypes = Collections.unmodifiableList(Arrays.asList(splitResponseTypes));

        // form_post response mode will be set if responseType includes "id_token" or "token"
        return RequestProcessor.requiresFormPostResponseMode((responseTypes));
    }

}
