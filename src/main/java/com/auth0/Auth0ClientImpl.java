package com.auth0;

import com.auth0.authentication.AuthenticationAPIClient;
import com.auth0.authentication.result.Credentials;
import com.auth0.authentication.result.UserProfile;
import org.apache.commons.lang3.Validate;

/**
 * Wrapper implementation around Auth0 service calls
 * to retrieve UserProfile and Tokens information
 */
public class Auth0ClientImpl implements Auth0Client {

    protected final String clientSecret;
    protected final AuthenticationAPIClient authenticationAPIClient;

    public Auth0ClientImpl(final String clientId, final String clientSecret, final String domain) {
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(domain);
        this.clientSecret = clientSecret;
        final Auth0 auth0 = new Auth0(clientId, clientSecret, domain);
        this.authenticationAPIClient = new AuthenticationAPIClient(auth0);
    }

    @Override
    public Tokens getTokens(final String authorizationCode, final String redirectUri) {
        Validate.notNull(authorizationCode);
        Validate.notNull(redirectUri);
        final Credentials creds = authenticationAPIClient
                .token(authorizationCode, redirectUri)
                .setClientSecret(clientSecret).execute();
        return new Tokens(creds.getIdToken(), creds.getAccessToken(), creds.getType(), creds.getRefreshToken());
    }

    @Override
    public Auth0User getUserProfile(final Tokens tokens) {
        Validate.notNull(tokens);
        final String idToken = tokens.getIdToken();
        final UserProfile userProfile = authenticationAPIClient.tokenInfo(idToken).execute();
        return new Auth0User(userProfile);
    }

}
