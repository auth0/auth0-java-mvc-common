package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.Response;
import com.auth0.net.TokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ConnectionTokenRequestTest {

    private static final String CONNECTION = "google-oauth2";
    private static final String SUBJECT_TOKEN = "subjectToken";
    private static final String SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token";
    private static final String DOMAIN = "domain.auth0.com";
    private static final String ISSUER = "https://domain.auth0.com/";

    @Mock
    private AuthAPI mockClient;
    @Mock
    private TokenRequest mockTokenRequest;
    @Mock
    private Response<TokenHolder> mockTokenResponse;
    @Mock
    private TokenHolder mockTokenHolder;

    @BeforeEach
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
    }

    @Test
    public void shouldDelegateToGetTokenForConnectionWithResolvedInputs() throws Exception {
        when(mockClient.getTokenForConnection(eq(CONNECTION), eq(SUBJECT_TOKEN), eq(SUBJECT_TOKEN_TYPE), isNull()))
                .thenReturn(mockTokenRequest);

        ConnectionTokenRequest request = new ConnectionTokenRequest(
                mockClient, CONNECTION, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, DOMAIN, ISSUER);

        request.execute();

        verify(mockClient).getTokenForConnection(CONNECTION, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, null);
    }

    @Test
    public void shouldPassLoginHintWhenProvided() throws Exception {
        when(mockClient.getTokenForConnection(eq(CONNECTION), eq(SUBJECT_TOKEN), eq(SUBJECT_TOKEN_TYPE), eq("google-user-id")))
                .thenReturn(mockTokenRequest);

        ConnectionTokenRequest request = new ConnectionTokenRequest(
                mockClient, CONNECTION, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, DOMAIN, ISSUER);

        request.withLoginHint("google-user-id").execute();

        verify(mockClient).getTokenForConnection(CONNECTION, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, "google-user-id");
    }

    @Test
    public void shouldMapTokenHolderToTokens() throws Exception {
        when(mockClient.getTokenForConnection(eq(CONNECTION), eq(SUBJECT_TOKEN), eq(SUBJECT_TOKEN_TYPE), isNull()))
                .thenReturn(mockTokenRequest);
        when(mockTokenHolder.getAccessToken()).thenReturn("federatedAccessToken");
        when(mockTokenHolder.getTokenType()).thenReturn("Bearer");
        when(mockTokenHolder.getExpiresIn()).thenReturn(3600L);
        when(mockTokenHolder.getScope()).thenReturn("openid");

        ConnectionTokenRequest request = new ConnectionTokenRequest(
                mockClient, CONNECTION, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, DOMAIN, ISSUER);

        Tokens tokens = request.execute();

        assertThat(tokens.getAccessToken(), is("federatedAccessToken"));
        assertThat(tokens.getIdToken(), is(nullValue()));
        assertThat(tokens.getRefreshToken(), is(nullValue()));
        assertThat(tokens.getType(), is("Bearer"));
        assertThat(tokens.getExpiresIn(), is(3600L));
        assertThat(tokens.getScope(), is("openid"));
        assertThat(tokens.getDomain(), is(DOMAIN));
        assertThat(tokens.getIssuer(), is(ISSUER));
    }

    @Test
    public void shouldPropagateAuth0Exception() throws Exception {
        when(mockClient.getTokenForConnection(eq(CONNECTION), eq(SUBJECT_TOKEN), eq(SUBJECT_TOKEN_TYPE), isNull()))
                .thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenThrow(Auth0Exception.class);

        ConnectionTokenRequest request = new ConnectionTokenRequest(
                mockClient, CONNECTION, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, DOMAIN, ISSUER);

        assertThrows(Auth0Exception.class, request::execute);
    }
}
