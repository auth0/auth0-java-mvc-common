package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.TokenRequest;

/**
 * Class to exchange a refresh token for a new set of {@link Tokens}, optionally targeting a
 * specific {@code audience} and/or {@code scope}. This exposes Auth0's refresh-token grant,
 * enabling Multi-Resource Refresh Token (MRRT) flows where one refresh token can obtain access
 * tokens for multiple APIs.
 * <p>
 * The library remains stateless: the application owns storage of the refresh token, caching of
 * the resulting access tokens, and any concurrency control around refresh-token rotation.
 * <p>
 * Obtain an instance via {@link AuthenticationController#renewAuth(String, String)} or
 * {@link AuthenticationController#renewAuth(String)}.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused"})
public class RenewAuthRequest {

    private final AuthAPI client;
    private final String refreshToken;
    private final String domain;
    private final String issuer;
    private String audience;
    private String scope;

    RenewAuthRequest(AuthAPI client, String refreshToken, String domain, String issuer) {
        this.client = client;
        this.refreshToken = refreshToken;
        this.domain = domain;
        this.issuer = issuer;
    }

    /**
     * Sets the audience to request an access token for. When not set, Auth0 uses the default
     * audience configured for the application.
     * <p>
     * Note: if the requested audience is not permitted by the application's MRRT policy, Auth0
     * does not error; it returns a token for the default audience instead. Callers must verify
     * the {@code aud} claim of the returned access token.
     *
     * @param audience the audience (API identifier) to request a token for.
     * @return this request instance for fluent chaining.
     */
    public RenewAuthRequest withAudience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Sets the scope to request for the access token.
     *
     * @param scope the requested scope.
     * @return this request instance for fluent chaining.
     */
    public RenewAuthRequest withScope(String scope) {
        this.scope = scope;
        return this;
    }

    /**
     * Executes the refresh-token grant against Auth0 and returns the resulting tokens.
     * <p>
     * The refresh-token grant does not return an ID token, so {@link Tokens#getIdToken()} is
     * typically null. When refresh-token rotation is enabled, the returned
     * {@link Tokens#getRefreshToken()} is a new refresh token that supersedes the one used here;
     * the application is responsible for persisting it.
     *
     * @return the {@link Tokens} obtained from the grant, including the granted scope.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     */
    public Tokens execute() throws Auth0Exception {
        TokenRequest request = client.renewAuth(refreshToken);
        if (audience != null) {
            request.setAudience(audience);
        }
        if (scope != null) {
            request.setScope(scope);
        }
        TokenHolder holder = request.execute().getBody();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(),
                holder.getTokenType(), holder.getExpiresIn(), holder.getScope(), domain, issuer);
    }
}
