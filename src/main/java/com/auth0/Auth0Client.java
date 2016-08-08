package com.auth0;

/**
 * Wrapper around API calls to retrieve tokens and user profile
 */
public interface Auth0Client {

    public Tokens getTokens(String authorizationCode, String redirectUri);

    public Auth0User getUserProfile(Tokens tokens);

}
