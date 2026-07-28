package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RenewAuthRequestTest {

    private static final String REFRESH_TOKEN = "refreshToken";
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
        when(mockClient.renewAuth(REFRESH_TOKEN)).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
    }

    @Test
    public void shouldNotSetAudienceOrScopeWhenNotProvided() throws Exception {
        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        request.execute();

        verify(mockTokenRequest, never()).setAudience(org.mockito.ArgumentMatchers.anyString());
        verify(mockTokenRequest, never()).setScope(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    public void shouldSetAudienceWhenProvided() throws Exception {
        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        request.withAudience("https://api.example.com").execute();

        verify(mockTokenRequest).setAudience("https://api.example.com");
        verify(mockTokenRequest, never()).setScope(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    public void shouldSetScopeWhenProvided() throws Exception {
        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        request.withScope("openid profile").execute();

        verify(mockTokenRequest).setScope("openid profile");
        verify(mockTokenRequest, never()).setAudience(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    public void shouldMapTokenHolderToTokensIncludingScope() throws Exception {
        when(mockTokenHolder.getAccessToken()).thenReturn("newAccessToken");
        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getRefreshToken()).thenReturn("rotatedRefreshToken");
        when(mockTokenHolder.getTokenType()).thenReturn("Bearer");
        when(mockTokenHolder.getExpiresIn()).thenReturn(86400L);
        when(mockTokenHolder.getScope()).thenReturn("openid profile");

        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        Tokens tokens = request.withAudience("https://api.example.com").withScope("openid profile").execute();

        assertThat(tokens.getAccessToken(), is("newAccessToken"));
        assertThat(tokens.getRefreshToken(), is("rotatedRefreshToken"));
        assertThat(tokens.getType(), is("Bearer"));
        assertThat(tokens.getExpiresIn(), is(86400L));
        assertThat(tokens.getScope(), is("openid profile"));
        assertThat(tokens.getDomain(), is(DOMAIN));
        assertThat(tokens.getIssuer(), is(ISSUER));
    }

    @Test
    public void shouldPropagateAuth0Exception() throws Exception {
        when(mockTokenRequest.execute()).thenThrow(Auth0Exception.class);

        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        assertThrows(Auth0Exception.class, request::execute);
    }

    @Test
    public void shouldGateRefreshWhenSessionCeilingHasPassed() throws Exception {
        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        assertThrows(SessionExpiredException.class,
                () -> request.withSessionExpiresAt(nowSeconds() - 3600).execute());

        verify(mockTokenRequest, never()).execute();
    }

    @Test
    public void shouldNotGateRefreshWhenSessionCeilingIsInFuture() throws Exception {
        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        request.withSessionExpiresAt(nowSeconds() + 3600).execute();

        verify(mockTokenRequest).execute();
    }

    @Test
    public void shouldNotGateRefreshWhenNoSessionCeilingSupplied() throws Exception {
        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        request.execute();

        verify(mockTokenRequest).execute();
    }

    @Test
    public void shouldCarryForwardSuppliedCeilingWhenResponseHasNone() throws Exception {
        when(mockTokenHolder.getIdToken()).thenReturn(null);
        long ceiling = nowSeconds() + 3600;

        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        Tokens tokens = request.withSessionExpiresAt(ceiling).execute();

        assertThat(tokens.getSessionExpiresAt(), is(ceiling));
    }

    @Test
    public void shouldLeaveCeilingNullWhenNoneSuppliedAndResponseHasNone() throws Exception {
        when(mockTokenHolder.getIdToken()).thenReturn(null);

        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        Tokens tokens = request.execute();

        assertThat(tokens.getSessionExpiresAt(), is(nullValue()));
    }

    @Test
    public void shouldKeepSuppliedCeilingEvenWhenResponseCarriesADifferentOne() throws Exception {
        // The ceiling is fixed at login (write-once): a session_expiry in the refresh response must
        // not move it. The response token is also unverified here, so its claims must not be trusted.
        long suppliedCeiling = nowSeconds() + 3600;
        when(mockTokenHolder.getIdToken()).thenReturn(idTokenWithSessionExpiry(nowSeconds() + 7200));

        RenewAuthRequest request = new RenewAuthRequest(mockClient, REFRESH_TOKEN, DOMAIN, ISSUER);

        Tokens tokens = request.withSessionExpiresAt(suppliedCeiling).execute();

        assertThat(tokens.getSessionExpiresAt(), is(suppliedCeiling));
    }

    private static long nowSeconds() {
        return Math.floorDiv(System.currentTimeMillis(), 1000L);
    }

    private static String idTokenWithSessionExpiry(long sessionExpiry) {
        return JWT.create()
                .withClaim("session_expiry", sessionExpiry)
                .sign(Algorithm.none());
    }
}
