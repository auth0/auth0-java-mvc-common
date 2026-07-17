package com.auth0;

import java.io.Serializable;

/**
 * Wrapper for the the user's credentials returned by Auth0.
 * <ul>
 * <li><i>accessToken</i>: Access Token for Auth0 API</li>
 * <li><i>idToken</i>: Identity Token with user information</li>
 * <li><i>refreshToken</i>: Refresh Token that can be used to request new tokens without signing in again</li>
 * <li><i>type</i>: Token Type</li>
 * <li><i>expiresIn</i>: Token expiration</li>
 * <li><i>sessionExpiresAt</i>: Upstream IdP session ceiling, from the {@code session_expiry} ID token claim</li>
 * </ul>
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class Tokens implements Serializable {

    private static final long serialVersionUID = 2371882820082543721L;

    /**
     * Default leeway, in seconds, applied when evaluating the {@code session_expiry} ceiling.
     * The session is treated as expired slightly <em>before</em> the wall-clock ceiling to
     * absorb clock skew between the application and the Auth0 platform.
     */
    public static final long DEFAULT_SESSION_EXPIRY_LEEWAY = 30;

    private final String accessToken;
    private final String idToken;
    private final String refreshToken;
    private final String type;
    private final Long expiresIn;
    private final String scope;
    private final String domain;
    private final String issuer;
    private final Long sessionExpiresAt;

    /**
     * @param accessToken  access token for Auth0 API
     * @param idToken      identity token with user information
     * @param refreshToken refresh token that can be used to request new tokens without signing in again
     * @param type         token type
     * @param expiresIn    token expiration
     */
    public Tokens(String accessToken, String idToken, String refreshToken, String type, Long expiresIn) {
        this(accessToken, idToken, refreshToken, type, expiresIn, null, null);
    }

    /**
     * Full constructor with domain information for MCD support.
     * <p>
     * Equivalent to calling {@link #Tokens(String, String, String, String, Long, String, String, Long)}
     * with a {@code null} {@code sessionExpiresAt} (no upstream IdP session ceiling).
     *
     * @param accessToken  access token for Auth0 API
     * @param idToken      identity token with user information
     * @param refreshToken refresh token that can be used to request new tokens
     *                     without signing in again
     * @param type         token type
     * @param expiresIn    token expiration
     * @param domain       the Auth0 domain that issued these tokens
     * @param issuer       the issuer URL from the ID token
     */
    public Tokens(String accessToken, String idToken, String refreshToken, String type, Long expiresIn, String domain, String issuer) {
        this(accessToken, idToken, refreshToken, type, expiresIn, null, domain, issuer, null);
    }

    /**
     * Full constructor including the granted scope and domain information.
     * <p>
     * Equivalent to calling {@link #Tokens(String, String, String, String, Long, String, String, String, Long)}
     * with a {@code null} {@code sessionExpiresAt} (no upstream IdP session ceiling).
     *
     * @param accessToken  access token for Auth0 API
     * @param idToken      identity token with user information
     * @param refreshToken refresh token that can be used to request new tokens
     *                     without signing in again
     * @param type         token type
     * @param expiresIn    token expiration
     * @param scope        the scope granted for the access token, or null if not provided
     * @param domain       the Auth0 domain that issued these tokens
     * @param issuer       the issuer URL from the ID token
     */
    public Tokens(String accessToken, String idToken, String refreshToken, String type, Long expiresIn, String scope, String domain, String issuer) {
        this(accessToken, idToken, refreshToken, type, expiresIn, scope, domain, issuer, null);
    }

    /**
     * Full constructor including the upstream IdP session ceiling.
     *
     * @param accessToken      access token for Auth0 API
     * @param idToken          identity token with user information
     * @param refreshToken     refresh token that can be used to request new tokens
     *                         without signing in again
     * @param type             token type
     * @param expiresIn        token expiration
     * @param scope        the scope granted for the access token, or null if not provided
     * @param domain           the Auth0 domain that issued these tokens
     * @param issuer           the issuer URL from the ID token
     * @param sessionExpiresAt the value of the {@code session_expiry} ID token claim
     *                         (Unix timestamp, seconds since epoch), or {@code null} when the
     *                         claim is absent. A {@code null} value means "no session ceiling"
     *                         and must never be treated as an already-expired session.
     */
    public Tokens(String accessToken, String idToken, String refreshToken, String type, Long expiresIn, String scope, String domain, String issuer, Long sessionExpiresAt) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.type = type;
        this.expiresIn = expiresIn;
        this.scope = scope;
        this.domain = domain;
        this.issuer = issuer;
        this.sessionExpiresAt = sessionExpiresAt;
    }

    /**
     * Getter for the Access Token.
     *
     * @return the Access Token.
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Getter for the Id Token.
     *
     * @return the Id Token.
     */
    public String getIdToken() {
        return idToken;
    }

    /**
     * Getter for the Refresh Token.
     *
     * @return the Refresh Token.
     */
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * Getter for the token Type .
     *
     * @return the Type of the token.
     */
    public String getType() {
        return type;
    }

    /**
     * Getter for the Expiration time of the Token.
     *
     * @return the expiration time.
     */
    public Long getExpiresIn() {
        return expiresIn;
    }

    /**
     * Getter for the scope granted for the Access Token.
     *
     * @return the granted scope, or null if not provided.
     */
    public String getScope() {
        return scope;
    }


    /**
     * Getter for the Auth0 domain that issued these tokens.
     * Used for domain-specific session management in Multiple Custom Domains (MCD)
     * scenarios.
     *
     * @return the domain that issued these tokens, or null for non-MCD scenarios
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Getter for the issuer URL from the ID token.
     * Used for domain-specific session management in Multiple Custom Domains (MCD)
     * scenarios.
     *
     * @return the issuer URL, or null for non-MCD scenarios
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Getter for the upstream IdP session ceiling, taken from the {@code session_expiry} claim
     * of the ID token at login (see the IPSIE SL1 profile). The value is an absolute point in
     * time expressed as a Unix timestamp in <strong>seconds</strong> since the epoch — not a
     * duration, and distinct from {@link #getExpiresIn()} (which bounds the access token).
     * <p>
     * This value is fixed at login and is not updated by a token refresh. It is {@code null}
     * when the connection did not emit the claim, in which case there is no session ceiling and
     * existing behavior is unchanged.
     * <p>
     * The library does not own a session, so it does not enforce this ceiling on your behalf.
     * The application must persist this value alongside the session and, on every session read,
     * treat the session as expired once {@link #isSessionExpired()} returns {@code true} —
     * redirecting the user to log in again. The same check must run before any refresh-token
     * exchange (see {@link #isSessionExpired()}).
     *
     * @return the {@code session_expiry} value in seconds since epoch, or {@code null} if the
     * claim was not present.
     */
    public Long getSessionExpiresAt() {
        return sessionExpiresAt;
    }

    /**
     * Convenience equivalent to {@link #isSessionExpired(long)} using
     * {@link #DEFAULT_SESSION_EXPIRY_LEEWAY}.
     *
     * @return {@code true} if the upstream IdP session ceiling has been reached, {@code false}
     * otherwise (including when no ceiling is present).
     */
    public boolean isSessionExpired() {
        return isSessionExpired(DEFAULT_SESSION_EXPIRY_LEEWAY);
    }

    /**
     * Whether the upstream IdP session ceiling ({@code session_expiry}) has been reached.
     * <p>
     * Call this on <strong>every</strong> session read and, critically, <strong>before</strong>
     * exchanging a refresh token: once the ceiling has passed the application must not call the
     * token endpoint with {@code grant_type=refresh_token}, and should surface a "session
     * expired" outcome and re-authenticate instead.
     * <p>
     * When no {@code session_expiry} was emitted ({@link #getSessionExpiresAt()} is {@code null}),
     * this always returns {@code false} — absence of the claim means "no ceiling" and must never
     * be treated as an expired session. The comparison is performed entirely in integer seconds.
     *
     * @param leewaySeconds a non-negative leeway, in seconds, applied so the session is treated
     *                      as expired slightly before the wall-clock ceiling to absorb clock
     *                      skew. Pass {@code 0} for an exact comparison.
     * @return {@code true} if a ceiling is present and {@code now >= sessionExpiresAt - leeway},
     * {@code false} otherwise.
     */
    public boolean isSessionExpired(long leewaySeconds) {
        if (sessionExpiresAt == null) {
            return false;
        }
        long nowSeconds = Math.floorDiv(System.currentTimeMillis(), 1000L);
        return nowSeconds >= sessionExpiresAt - leewaySeconds;
    }
}
