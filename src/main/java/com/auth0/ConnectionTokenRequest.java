package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.TokenRequest;

/**
 * Class to exchange an Auth0 token for an external identity provider's access token via
 * <a href="https://auth0.com/docs/secure/tokens/token-vault">Token Vault</a> (the
 * federated-connection access-token grant). The returned access token is the external provider's
 * token (for example Google, GitHub, or Slack), opaque to this application, suitable for calling
 * that provider's API on the user's behalf.
 * <p>
 * The subject token may be an Auth0 refresh token or access token; the subject-token-type is fixed
 * by the factory method used to create this request. The federated-connection grant returns an
 * access token, {@code scope}, {@code expires_in}, and {@code token_type} — no ID token and no
 * refresh token.
 * <p>
 * The library remains stateless: the application owns storage of the subject token, caching of the
 * resulting connection access token, and any concurrency control.
 * <p>
 * Obtain an instance via one of the {@code AuthenticationController} factory methods:
 * {@link AuthenticationController#getTokenForConnectionWithRefreshToken(String, String)},
 * {@link AuthenticationController#getTokenForConnectionWithAccessToken(String, String)}, or
 * {@link AuthenticationController#getTokenForConnection(String, String, String)} (and their
 * domain / request overloads).
 */
@SuppressWarnings({"UnusedReturnValue", "WeakerAccess", "unused"})
public class ConnectionTokenRequest {

    private final AuthAPI client;
    private final String connection;
    private final String subjectToken;
    private final String subjectTokenType;
    private final String domain;
    private final String issuer;
    private String loginHint;

    ConnectionTokenRequest(AuthAPI client, String connection, String subjectToken,
                           String subjectTokenType, String domain, String issuer) {
        this.client = client;
        this.connection = connection;
        this.subjectToken = subjectToken;
        this.subjectTokenType = subjectTokenType;
        this.domain = domain;
        this.issuer = issuer;
    }

    /**
     * Sets the {@code login_hint} — the user's ID within the identity provider specified by the
     * connection (for example, the Google user ID when the connection is {@code google-oauth2}).
     * When not set, no {@code login_hint} is sent.
     *
     * @param loginHint the provider-side identity provider user ID.
     * @return this request instance for fluent chaining.
     */
    public ConnectionTokenRequest withLoginHint(String loginHint) {
        this.loginHint = loginHint;
        return this;
    }

    /**
     * Executes the federated-connection token exchange against Auth0 and returns the resulting
     * tokens. The returned {@link Tokens#getAccessToken()} is the external provider's access token;
     * {@link Tokens#getIdToken()} and {@link Tokens#getRefreshToken()} are null.
     *
     * @return the {@link Tokens} obtained from the grant.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     */
    public Tokens execute() throws Auth0Exception {
        TokenRequest request = client.getTokenForConnection(connection, subjectToken, subjectTokenType, loginHint);
        TokenHolder holder = request.execute().getBody();
        return new Tokens(holder.getAccessToken(), null, null,
                holder.getTokenType(), holder.getExpiresIn(), holder.getScope(), domain, issuer);
    }
}
