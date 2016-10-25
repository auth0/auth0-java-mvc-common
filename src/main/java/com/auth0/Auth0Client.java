package com.auth0;

/**
 * Wrapper around API calls to retrieve tokens and user profile
 */
public interface Auth0Client {

    /**
     * Fetch the token information from Auth0, using the authorization_code grant type
     *
     * For Public Client, e.g. Android apps ,you need to provide the code_verifier
     * used to generate the challenge sent to Auth0 {@literal /authorize} method like:
     *
     * @param authorizationCode the authorization code received from the /authorize call.
     * @param redirectUri       the uri sent to /authorize as the 'redirect_uri'.
     * @return a request to obtain access_token by exchanging a authorization code.
     */
    Tokens getTokens(String authorizationCode, String redirectUri);

    /**
     * Fetch the token information from Auth0
     *
     * @param tokens the tokens used to fetch information (idToken)
     * @return a request to start
     */
    Auth0User getUserProfile(Tokens tokens);

}
