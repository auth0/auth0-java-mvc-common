package com.auth0;

import java.io.Serializable;

/**
 * Holds the user's credentials returned by Auth0.
 * <ul>
 * <li><i>idToken</i>: Identity Token with user information</li>
 * <li><i>accessToken</i>: Access Token for Auth0 API</li>
 * <li><i>type</i>: Token Type</li>
 * <li><i>refreshToken</i>: Refresh Token that can be used to request new tokens without signing in again</li>
 * </ul>
 */
public class Tokens implements Serializable {

    private static final long serialVersionUID = 2371882820082543721L;

    private String idToken;
    private String accessToken;
    private String type;
    private String refreshToken;

    /**
     *
     * @param idToken identity token with user information
     * @param accessToken access token for Auth0 API
     * @param type token type
     * @param refreshToken refresh token that can be used to request new tokens without signing in again
     */
    public Tokens(final String idToken, final String accessToken, final String type, final String refreshToken) {
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.type = type;
        this.refreshToken = refreshToken;
    }

    public String getIdToken() {
        return idToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getType() {
        return type;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
