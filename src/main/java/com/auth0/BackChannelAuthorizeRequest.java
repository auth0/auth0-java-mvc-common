package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.BackChannelAuthorizeResponse;

import java.util.Map;

/**
 * Class to initiate a Client-Initiated Backchannel Authentication (CIBA) backchannel authorization
 * request (POST /bc-authorize). This is the first step of the CIBA flow: the application requests
 * authentication from Auth0 for a user identified via login hints, and Auth0 returns an
 * {@code auth_req_id} that can be polled to obtain the authentication result.
 * <p>
 * The returned {@link BackChannelAuthorizeResponse} carries:
 * <ul>
 *   <li>{@code auth_req_id}: a unique identifier for this authentication request, used in the
 *       subsequent poll step to fetch the result.</li>
 *   <li>{@code expires_in}: the lifetime of the authentication request in seconds; after this
 *       period, the auth_req_id is no longer valid.</li>
 *   <li>{@code interval}: the minimum number of seconds the application should wait between
 *       consecutive poll requests.</li>
 * </ul>
 * <p>
 * The library remains stateless: the application owns the polling loop, storage of the
 * {@code auth_req_id}, and any state associated with the authentication request. See
 * {@link AuthenticationController} for the entry point to obtain an instance.
 * <p>
 * Optional parameters ({@code audience}, {@code requested_expiry}) can be configured via
 * {@link #withAudience(String)} and {@link #withRequestedExpiry(Integer)}.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused"})
public class BackChannelAuthorizeRequest {

    private final AuthAPI client;
    private final String scope;
    private final String bindingMessage;
    private final Map<String, Object> loginHint;
    private final String domain;
    private final String issuer;
    private String audience;
    private Integer requestedExpiry;

    BackChannelAuthorizeRequest(AuthAPI client, String scope, String bindingMessage,
                                Map<String, Object> loginHint, String domain, String issuer) {
        this.client = client;
        this.scope = scope;
        this.bindingMessage = bindingMessage;
        this.loginHint = loginHint;
        this.domain = domain;
        this.issuer = issuer;
    }

    /**
     * Sets the audience (API identifier) for the access token to be obtained during the
     * authentication flow. When not set, Auth0 uses the default audience configured for the
     * application.
     *
     * @param audience the audience to request a token for.
     * @return this request instance for fluent chaining.
     */
    public BackChannelAuthorizeRequest withAudience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Sets the requested expiry (lifetime) of the authentication request in seconds. This value
     * is sent to Auth0 as {@code requested_expiry} and controls how long the {@code auth_req_id}
     * remains valid for polling.
     *
     * @param seconds the requested lifetime of the authentication request.
     * @return this request instance for fluent chaining.
     */
    public BackChannelAuthorizeRequest withRequestedExpiry(Integer seconds) {
        this.requestedExpiry = seconds;
        return this;
    }

    /**
     * Executes the backchannel authorization request against Auth0 and returns the response
     * containing the {@code auth_req_id}, expiration, and polling interval.
     *
     * @return the {@link BackChannelAuthorizeResponse} containing {@code auth_req_id},
     *         {@code expires_in}, and {@code interval}.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     */
    public BackChannelAuthorizeResponse execute() throws Auth0Exception {
        com.auth0.net.Request<BackChannelAuthorizeResponse> request;

        if (audience == null && requestedExpiry == null) {
            request = client.authorizeBackChannel(scope, bindingMessage, loginHint);
        } else {
            request = client.authorizeBackChannel(scope, bindingMessage, loginHint,
                    audience, requestedExpiry);
        }

        return request.execute().getBody();
    }
}
