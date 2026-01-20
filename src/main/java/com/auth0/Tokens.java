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
 * </ul>
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class Tokens implements Serializable {

    private static final long serialVersionUID = 2371882820082543721L;

    private final String accessToken;
    private final String idToken;
    private final String refreshToken;
    private final String type;
    private final Long expiresIn;
    private final String domain;
    private final String issuer;

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
     * Full constructor with domain information for MCD support
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
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.type = type;
        this.expiresIn = expiresIn;
        this.domain = domain;
        this.issuer = issuer;
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
     * Getter for the Auth0 domain that issued these tokens.
     * Used for domain-specific session management in Multi-Customer Domain (MCD)
     * scenarios.
     *
     * @return the domain that issued these tokens, or null for non-MCD scenarios
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Getter for the issuer URL from the ID token.
     * Used for domain-specific session management in Multi-Customer Domain (MCD)
     * scenarios.
     *
     * @return the issuer URL, or null for non-MCD scenarios
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Validates that these tokens belong to the specified domain.
     * Used to prevent cross-domain session leakage in MCD scenarios.
     *
     * @param expectedDomain the expected domain for these tokens
     * @return true if tokens belong to the expected domain, false otherwise
     */
    public boolean belongsToDomain(String expectedDomain) {
        if (domain == null || expectedDomain == null) {
            // Non-MCD scenario - no domain validation needed
            return true;
        }
        return domain.equals(expectedDomain);
    }

    /**
     * Validates that these tokens have the specified issuer.
     * Used to prevent cross-domain session leakage in MCD scenarios.
     *
     * @param expectedIssuer the expected issuer for these tokens
     * @return true if tokens have the expected issuer, false otherwise
     */
    public boolean hasIssuer(String expectedIssuer) {
        if (issuer == null || expectedIssuer == null) {
            // Non-MCD scenario - no issuer validation needed
            return true;
        }

        // Normalize both for comparison
        String normalizedTokenIssuer = normalizeIssuer(issuer);
        String normalizedExpectedIssuer = normalizeIssuer(expectedIssuer);

        return normalizedTokenIssuer.equals(normalizedExpectedIssuer);
    }

    /**
     * Normalizes an issuer URL for comparison.
     */
    private String normalizeIssuer(String issuer) {
        if (issuer == null)
            return null;

        String normalized = issuer.trim();
        if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
            normalized = "https://" + normalized;
        }
        if (!normalized.endsWith("/")) {
            normalized = normalized + "/";
        }
        return normalized;
    }
}
