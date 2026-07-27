package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.TokenRequest;

import static com.auth0.Tokens.DEFAULT_SESSION_EXPIRY_LEEWAY;

/**
 * Class to exchange a refresh token for a new set of {@link Tokens}, optionally targeting a
 * specific {@code audience} and/or {@code scope}. This exposes Auth0's refresh-token grant,
 * enabling Multi-Resource Refresh Token (MRRT) flows where one refresh token can obtain access
 * tokens for multiple APIs.
 * <p>
 * The library remains stateless: the application owns storage of the refresh token, caching of
 * the resulting access tokens, and any concurrency control around refresh-token rotation.
 * <p>
 * Obtain an instance via {@link AuthenticationController#renewAuth(String, String)},
 * {@link AuthenticationController#renewAuth(String)}, or
 * {@link AuthenticationController#renewAuth(String, jakarta.servlet.http.HttpServletRequest)}.
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused"})
public class RenewAuthRequest {

    private final AuthAPI client;
    private final String refreshToken;
    private final String domain;
    private final String issuer;
    private String audience;
    private String scope;
    private Long sessionExpiresAt;

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
     * Supplies the upstream IdP session ceiling ({@code session_expiry}, see the IPSIE SL1 profile)
     * that the application persisted at login from {@link Tokens#getSessionExpiresAt()}. The library
     * is stateless and does not remember it across requests, so it must be handed back here for the
     * ceiling to be enforced on refresh.
     * <p>
     * When set, {@link #execute()} enforces the ceiling in two ways:
     * <ul>
     *   <li><strong>Gate:</strong> if the ceiling has already passed, {@link #execute()} throws a
     *   {@link SessionExpiredException} <em>before</em> contacting the token endpoint, so a renewed
     *   access token can never outlive the session ceiling.</li>
     *   <li><strong>Carry-forward:</strong> the refresh-token grant returns no ID token (hence no
     *   fresh {@code session_expiry}), so the returned {@link Tokens} carries this same ceiling
     *   forward via {@link Tokens#getSessionExpiresAt()} rather than dropping it to {@code null}
     *   ("no ceiling"). Only a newly-emitted, valid {@code session_expiry} in the response replaces
     *   it.</li>
     * </ul>
     * Passing {@code null} (the default) means "no known ceiling": no gate is applied and the
     * returned tokens carry no ceiling unless the response itself provides one.
     *
     * @param sessionExpiresAt the persisted {@code session_expiry} ceiling (Unix seconds), or
     *                         {@code null} for no ceiling.
     * @return this request instance for fluent chaining.
     */
    public RenewAuthRequest withSessionExpiresAt(Long sessionExpiresAt) {
        this.sessionExpiresAt = sessionExpiresAt;
        return this;
    }

    /**
     * Executes the refresh-token grant against Auth0 and returns the resulting tokens.
     * <p>
     * The refresh-token grant does not return an ID token, so {@link Tokens#getIdToken()} is
     * typically null. When refresh-token rotation is enabled, the returned
     * {@link Tokens#getRefreshToken()} is a new refresh token that supersedes the one used here;
     * the application is responsible for persisting it.
     * <p>
     * When a session ceiling was supplied via {@link #withSessionExpiresAt(Long)}, it is enforced:
     * an already-passed ceiling short-circuits with a {@link SessionExpiredException} before any
     * network call, and the ceiling is carried forward onto the returned tokens (see that method).
     *
     * @return the {@link Tokens} obtained from the grant, including the granted scope.
     * @throws SessionExpiredException if the supplied session ceiling has already passed.
     * @throws Auth0Exception          if the request to the Auth0 server failed.
     */
    public Tokens execute() throws Auth0Exception, SessionExpiredException {
        // Gate: never refresh past the IdP session ceiling — the renewed access token must not
        // outlive the session. Checked before the network call so no token is minted.
        if (Tokens.isSessionExpired(sessionExpiresAt, DEFAULT_SESSION_EXPIRY_LEEWAY)) {
            throw new SessionExpiredException(
                    "The session_expiry ceiling has passed; the refresh token must not be exchanged. Re-authenticate instead.");
        }

        TokenRequest request = client.renewAuth(refreshToken);
        if (audience != null) {
            request.setAudience(audience);
        }
        if (scope != null) {
            request.setScope(scope);
        }
        TokenHolder holder = request.execute().getBody();

        // Carry-forward: prefer a fresh, valid ceiling from the response (rare — the grant has no
        // ID token), otherwise re-stamp the supplied ceiling so a refresh never silently drops it.
        Long freshCeiling = RequestProcessor.parseSessionExpiry(holder.getIdToken());
        Long ceiling = freshCeiling != null ? freshCeiling : sessionExpiresAt;

        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(),
                holder.getTokenType(), holder.getExpiresIn(), holder.getScope(), domain, issuer, ceiling);
    }
}
