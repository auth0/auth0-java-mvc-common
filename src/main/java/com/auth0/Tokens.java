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

    /**
     * @param accessToken  access token for Auth0 API
     * @param idToken      identity token with user information
     * @param refreshToken refresh token that can be used to request new tokens without signing in again
     * @param type         token type
     * @param expiresIn    token expiration
     */
    public Tokens(String accessToken, String idToken, String refreshToken, String type, Long expiresIn) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.type = type;
        this.expiresIn = expiresIn;
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
}
