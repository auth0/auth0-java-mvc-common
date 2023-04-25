package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.PushedAuthorizationResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static com.auth0.IdentityVerificationException.API_ERROR;

public class PushedAuthorizationRequest {

    private static final String SCOPE_OPENID = "openid";

    private HttpServletResponse response;
    private HttpServletRequest request;
    private final AuthAPI authAPI;
    private final String redirectUrl;
    private final String responseType;
    private final Map<String, String> additionalParams = new HashMap<>();
    private boolean useLegacySameSiteCookie = true;
    private boolean setSecureCookie = false;
    private String nonce;
    private String state;

    private boolean used;

    PushedAuthorizationRequest(AuthAPI client, HttpServletRequest request, HttpServletResponse response, String redirectUrl, String responseType) {
        this.request = request;
        this.response = response;
        this.responseType = responseType;
        this.redirectUrl = redirectUrl; // TODO null check here or elsewhere?
        this.authAPI = client;
        this.additionalParams.put("scope", SCOPE_OPENID);
    }

    PushedAuthorizationRequest withOrganization(String organization) {
        this.additionalParams.put("organization", organization);
        return this;
    }

    PushedAuthorizationRequest withInvitation(String invitation) {
        this.additionalParams.put("invitation", invitation);
        return this;
    }

    PushedAuthorizationRequest withConnection(String connection) {
        this.additionalParams.put("connection", connection);
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
    public PushedAuthorizationRequest withSecureCookie(boolean secureCookie) {
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
    PushedAuthorizationRequest withLegacySameSiteCookie(boolean useLegacySameSiteCookie) {
        this.useLegacySameSiteCookie = useLegacySameSiteCookie;
        return this;
    }

    public PushedAuthorizationRequest withAudience(String audience) {
        this.additionalParams.put("audience", audience);
        return this;
    }

    public PushedAuthorizationRequest withState(String state) {
        this.state = state;
        this.additionalParams.put("state", state);
        return this;
    }

    public PushedAuthorizationRequest withNonce(String nonce) {
        this.nonce = nonce;
        this.additionalParams.put("nonce", nonce);
        return this;
    }

    public PushedAuthorizationRequest withScope(String scope) {
        this.additionalParams.put("scope", scope);
        return this;
    }

    /**
     * Sets an additional parameter.
     *
     * @param name  name of the parameter
     * @param value value of the parameter to set
     * @return the builder instance
     */
    public PushedAuthorizationRequest withParameter(String name, String value) {
        if ("state".equals(name) || "nonce".equals(name)) {
            throw new IllegalArgumentException("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.");
        }
        if ("response_type".equals(name)) {
            throw new IllegalArgumentException("Response type cannot be changed once set.");
        }
        if ("redirect_uri".equals(name)) {
            throw new IllegalArgumentException("Redirect URI cannot be changed once set.");
        }
        this.additionalParams.put(name, value);
        return this;
    }

    public String execute() throws IllegalStateException, InvalidRequestException {
        if (used) {
            throw new IllegalStateException("The AuthorizeUrl instance must not be reused.");
        }

        TransientCookieManager.store(request, response, state, nonce, useLegacySameSiteCookie, setSecureCookie, responseType);
        used = true;

        try {
            PushedAuthorizationResponse pushedAuthResponse = authAPI.pushedAuthorizationRequest(redirectUrl, responseType, additionalParams).execute();
            String requestUri = pushedAuthResponse.getRequestURI();
            if (requestUri == null || requestUri.isEmpty()) {
                throw new InvalidRequestException(API_ERROR, "The PAR request returned a missing or empty request_uri value");
            }
            if (pushedAuthResponse.getExpiresIn() == null) {
                throw new InvalidRequestException(API_ERROR, "The PAR request returned a missing expires_in value");
            }
            return authAPI.pushedAuthorizationUrl(pushedAuthResponse.getRequestURI());
        } catch (Auth0Exception e) {
            throw new InvalidRequestException(API_ERROR, e.getMessage(), e);
        }
    }
}
