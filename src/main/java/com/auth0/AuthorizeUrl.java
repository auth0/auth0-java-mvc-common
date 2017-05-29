package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.auth.AuthorizeUrlBuilder;

import javax.servlet.http.HttpServletRequest;

/**
 * Class to create and customize an Auth0 Authorize URL.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused", "SameParameterValue"})
public class AuthorizeUrl {

    private static final String SCOPE_OPENID = "openid";
    private final AuthorizeUrlBuilder builder;

    AuthorizeUrl(AuthAPI client, String redirectUrl, String responseType) {
        builder = client.authorizeUrl(redirectUrl)
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
     * @param request request where the state will be saved
     * @param state   state to set
     * @return the builder instance
     */
    public AuthorizeUrl withState(HttpServletRequest request, String state) {
        RandomStorage.setSessionState(request, state);
        builder.withState(state);
        return this;
    }

    /**
     * Sets the nonce value.
     *
     * @param request request where the nonce will be saved
     * @param nonce   nonce to set
     * @return the builder instance
     */
    public AuthorizeUrl withNonce(HttpServletRequest request, String nonce) {
        RandomStorage.setSessionNonce(request, nonce);
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
     *
     * @return the string URL
     */
    public String build() {
        return builder.build();
    }

}
