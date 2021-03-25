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
    private boolean useLegacySameSiteCookie = true;
    private boolean setSecureCookie = false;
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
     * Sets the organization parameter on the authorize URL
     * @param organization The organization parameter value
     * @return this builder instance
     */
    public AuthorizeUrl withOrganization(String organization) {
        builder.withOrganization(organization);
        return this;
    }

    /**
     * Sets the invitation parameter on the authorize URL
     * @param invitation The invitation parameter value
     * @return this builder instance
     */
    public AuthorizeUrl withInvitation(String invitation) {
        builder.withInvitation(invitation);
        return this;
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
     * Sets whether cookies used during the authentication flow have the {@code Secure} attribute set or not.
     * By default, cookies will be set with the Secure attribute if the responseType includes {@code id_token} and thus requires
     * the {@code SameSite=None} cookie attribute set. Setting this to false will <strong>not</strong> override this behavior,
     * as clients will reject cookies with {@code SameSite=None} unless the {@code Secure} attribute is set.
     *
     * While not guaranteed by all clients, generally a cookie with the {@code Secure} attribute will be rejected unless
     * served over HTTPS.
     *
     * @param secureCookie whether to always set the Secure attribute on all cookies.
     * @return the builder instance.
     */
    public AuthorizeUrl withSecureCookie(boolean secureCookie) {
        this.setSecureCookie = secureCookie;
        return this;
    }

    /**
     * Sets whether a fallback cookie should be used for clients that do not support "SameSite=None".
     * Only applicable when this instance is created with {@link AuthorizeUrl#AuthorizeUrl(AuthAPI, HttpServletRequest, HttpServletResponse, String, String)}.
     *
     * @param useLegacySameSiteCookie whether or not to set fallback auth cookies for clients that do not support "SameSite=None"
     * @return the builder instance
     */
    AuthorizeUrl withLegacySameSiteCookie(boolean useLegacySameSiteCookie) {
        this.useLegacySameSiteCookie = useLegacySameSiteCookie;
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
            SameSite sameSiteValue = containsFormPost() ? SameSite.NONE : SameSite.LAX;

            TransientCookieStore.storeState(response, state, sameSiteValue, useLegacySameSiteCookie, setSecureCookie);
            TransientCookieStore.storeNonce(response, nonce, sameSiteValue, useLegacySameSiteCookie, setSecureCookie);
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
        return RequestProcessor.requiresFormPostResponseMode(responseTypes);
    }

}
