package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.BackChannelTokenResponse;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.net.Request;
import com.auth0.net.Response;
import com.auth0.net.TokenRequest;
import com.auth0.net.client.Auth0HttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RequestProcessorTest {

    private static final String DOMAIN = "test-domain.auth0.com";
    private static final String ISSUER = "https://test-domain.auth0.com/";
    private static final String CLIENT_ID = "testClientId";
    private static final String CLIENT_SECRET = "testClientSecret";
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String RESPONSE_TYPE_TOKEN = "token";
    private static final String RESPONSE_TYPE_ID_TOKEN = "id_token";

    @Mock
    private DomainProvider mockDomainProvider;
    @Mock
    private JwkProvider mockJwkProvider;
    @Mock
    private Auth0HttpClient mockHttpClient;
    @Mock
    private AuthAPI mockAuthAPI;
    @Mock
    private TokenRequest mockTokenRequest;
    @Mock
    private Response<TokenHolder> mockTokenResponse;
    @Mock
    private TokenHolder mockTokenHolder;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        request.setSecure(true);
    }

    // --- Builder Tests ---

    @Test
    public void shouldBuildRequestProcessorWithRequiredParameters() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldBuildRequestProcessorWithAllOptionalParameters() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withJwkProvider(mockJwkProvider)
                .withClockSkew(120)
                .withAuthenticationMaxAge(3600)
                .withCookiePath("/custom")
                .withLegacySameSiteCookie(false)
                .withOrganization("org_123")
                .withInvitation("inv_456")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    // --- Legacy SameSite Cookie Tests ---

    @Test
    public void shouldSetDefaultLegacySameSiteCookieToTrue() {
        RequestProcessor processor = createDefaultRequestProcessor();

        assertThat(processor.useLegacySameSiteCookie, is(true));
    }

    @Test
    public void shouldDisableLegacySameSiteCookie() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withLegacySameSiteCookie(false)
                .build();

        assertThat(processor.useLegacySameSiteCookie, is(false));
    }

    // --- Domain Handling Tests ---

    @Test
    public void shouldGetDomainFromProvider() {
        String expectedDomain = "custom-domain.auth0.com";
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(expectedDomain);

        RequestProcessor processor = createDefaultRequestProcessor();
        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        verify(mockDomainProvider).getDomain(request);
        verify(spy).createClientForDomain(expectedDomain);
    }

    @Test
    public void shouldCreateClientForDomain() {
        RequestProcessor processor = createDefaultRequestProcessor();

        AuthAPI result = processor.createClientForDomain(DOMAIN);

        assertThat(result, is(notNullValue()));
    }

    // --- RenewAuth Tests ---

    @Test
    public void shouldBuildRenewAuthRequestForExplicitDomain() {
        RequestProcessor processor = createDefaultRequestProcessor();
        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        RenewAuthRequest result = spy.buildRenewAuthRequest("refreshToken", DOMAIN);

        assertThat(result, is(notNullValue()));
        verify(spy).createClientForDomain(DOMAIN);
    }

    @Test
    public void shouldBuildRenewAuthRequestFromStaticDomain() {
        RequestProcessor processor = new RequestProcessor.Builder(
                new StaticDomainProvider(DOMAIN),
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withJwkProvider(mockJwkProvider)
                .build();
        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        RenewAuthRequest result = spy.buildRenewAuthRequest("refreshToken");

        assertThat(result, is(notNullValue()));
        verify(spy).createClientForDomain(DOMAIN);
    }

    @Test
    public void shouldThrowOnNoArgRenewAuthWhenUsingResolver() {
        RequestProcessor processor = createDefaultRequestProcessor();

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> processor.buildRenewAuthRequest("refreshToken"));
        assertThat(exception.getMessage(), containsString("A domain is required when using a DomainResolver"));
    }

    @Test
    public void shouldBuildRenewAuthRequestResolvingDomainFromRequest() {
        String resolvedDomain = "resolved-domain.auth0.com";
        when(mockDomainProvider.getDomain(request)).thenReturn(resolvedDomain);

        RequestProcessor processor = createDefaultRequestProcessor();
        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        RenewAuthRequest result = spy.buildRenewAuthRequest("refreshToken", request);

        assertThat(result, is(notNullValue()));
        verify(mockDomainProvider).getDomain(request);
        verify(spy).createClientForDomain(resolvedDomain);
    }

    // --- Custom Token Exchange Tests ---

    @Test
    public void shouldBuildTokenExchangeRequestForExplicitDomain() {
        RequestProcessor processor = createDefaultRequestProcessor();

        TokenExchangeRequest result = processor.buildTokenExchangeRequest("subjectToken", "custom:token", DOMAIN, false);

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildLoginTokenExchangeRequestForExplicitDomain() {
        RequestProcessor processor = createDefaultRequestProcessor();

        TokenExchangeRequest result = processor.buildTokenExchangeRequest("subjectToken", "custom:token", DOMAIN, true);

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildTokenExchangeRequestFromStaticDomain() {
        RequestProcessor processor = new RequestProcessor.Builder(
                new StaticDomainProvider(DOMAIN),
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withJwkProvider(mockJwkProvider)
                .build();

        TokenExchangeRequest result = processor.buildTokenExchangeRequest("subjectToken", "custom:token", false);

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldThrowOnNoDomainTokenExchangeWhenUsingResolver() {
        RequestProcessor processor = createDefaultRequestProcessor();

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> processor.buildTokenExchangeRequest("subjectToken", "custom:token", false));
        assertThat(exception.getMessage(), containsString("A domain is required when using a DomainResolver"));
    }

    @Test
    public void shouldExecuteCustomTokenExchangeViaAuthApiAndReturnTokens() throws Exception {
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getAccessToken()).thenReturn("cteAccessToken");
        when(mockTokenHolder.getRefreshToken()).thenReturn("cteRefreshToken");
        when(mockTokenHolder.getTokenType()).thenReturn("Bearer");
        when(mockTokenHolder.getExpiresIn()).thenReturn(3600L);
        when(mockTokenHolder.getScope()).thenReturn("openid profile");

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        Tokens tokens = spy.executeCustomTokenExchange(
                "subjectToken", "custom:token", null, null, null, DOMAIN, ISSUER, false);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("cteAccessToken"));
        assertThat(tokens.getRefreshToken(), is("cteRefreshToken"));
        assertThat(tokens.getType(), is("Bearer"));
        assertThat(tokens.getExpiresIn(), is(3600L));
        verify(mockAuthAPI).exchangeToken("subjectToken", "custom:token");
    }

    @Test
    public void shouldForwardAudienceScopeAndOrganizationOnCustomTokenExchange() throws Exception {
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getIdToken()).thenReturn(null);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        spy.executeCustomTokenExchange(
                "subjectToken", "custom:token", "https://api/", "openid profile", null,
                DOMAIN, ISSUER, false);

        verify(mockTokenRequest).setAudience("https://api/");
        verify(mockTokenRequest).setScope("openid profile");
        verify(mockTokenRequest, never()).addParameter(eq("organization"), any());
    }

    @Test
    public void shouldPassOrganizationOnCustomTokenExchangeWhenProvided() throws Exception {
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        // Utility path with an organization set still returns tokens; ID token verification is
        // skipped here because the holder has no ID token.
        when(mockTokenHolder.getIdToken()).thenReturn(null);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        spy.executeCustomTokenExchange(
                "subjectToken", "custom:token", null, null, "org_123",
                DOMAIN, ISSUER, false);

        verify(mockTokenRequest).addParameter("organization", "org_123");
    }

    @Test
    public void shouldThrowMissingIdTokenOnLoginCustomTokenExchangeWhenNoIdTokenReturned() throws Exception {
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getIdToken()).thenReturn(null);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        InvalidRequestException exception = assertThrows(
                InvalidRequestException.class,
                () -> spy.executeCustomTokenExchange(
                        "subjectToken", "custom:token", null, null, null,
                        DOMAIN, ISSUER, true));
        assertThat(exception.getCode(), is("a0.missing_id_token"));
    }

    @Test
    public void shouldThrowOnLoginCustomTokenExchangeWhenIdTokenVerificationFails() throws Exception {
        // Structurally valid JWT with an invalid signature so RS256 verification fails.
        String fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3dyb25nLyIsInN1YiI6InVzZXIxMjMiLCJhdWQiOiJ0ZXN0Q2xpZW50SWQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMH0.signature";
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getIdToken()).thenReturn(fakeJwt);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        IdentityVerificationException exception = assertThrows(
                IdentityVerificationException.class,
                () -> spy.executeCustomTokenExchange(
                        "subjectToken", "custom:token", null, "openid", null,
                        DOMAIN, ISSUER, true));
        assertThat(exception.getCode(), is("a0.invalid_jwt_error"));
    }

    @Test
    public void shouldReturnVerifiedTokensOnLoginCustomTokenExchangeWhenIdTokenValid() throws Exception {
        String idToken = signedIdToken(null);
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getIdToken()).thenReturn(idToken);
        when(mockTokenHolder.getAccessToken()).thenReturn("cteAccessToken");

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        Tokens tokens = spy.executeCustomTokenExchange(
                "subjectToken", "custom:token", null, "openid", null, DOMAIN, ISSUER, true);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getIdToken(), is(idToken));
        assertThat(tokens.getAccessToken(), is("cteAccessToken"));
    }

    @Test
    public void shouldReturnTokensOnUtilityCustomTokenExchangeWhenOrgClaimMatches() throws Exception {
        String idToken = signedIdToken("org_123");
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getIdToken()).thenReturn(idToken);
        when(mockTokenHolder.getAccessToken()).thenReturn("cteAccessToken");

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        Tokens tokens = spy.executeCustomTokenExchange(
                "subjectToken", "custom:token", null, "openid", "org_123", DOMAIN, ISSUER, false);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("cteAccessToken"));
        verify(mockTokenRequest).addParameter("organization", "org_123");
    }

    @Test
    public void shouldThrowOnUtilityCustomTokenExchangeWhenOrgClaimMismatches() throws Exception {
        String idToken = signedIdToken("org_other");
        when(mockAuthAPI.exchangeToken("subjectToken", "custom:token")).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getIdToken()).thenReturn(idToken);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);

        IdentityVerificationException exception = assertThrows(
                IdentityVerificationException.class,
                () -> spy.executeCustomTokenExchange(
                        "subjectToken", "custom:token", null, "openid", "org_123", DOMAIN, ISSUER, false));
        assertThat(exception.getCode(), is("a0.invalid_jwt_error"));
    }

    // --- CIBA Backchannel Poll Tests ---

    @Test
    public void shouldTranslateAuthorizationPendingIntoBackChannelException() throws Exception {
        Request<BackChannelTokenResponse> pollRequest = stubPollRequestThatThrows(
                apiException("authorization_pending", "User has not yet approved."));

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);
        when(mockAuthAPI.getBackChannelLoginStatus("auth-req-123", CIBA_GRANT_TYPE)).thenReturn(pollRequest);

        BackChannelAuthorizationException exception = assertThrows(
                BackChannelAuthorizationException.class,
                () -> spy.executeBackChannelPoll("auth-req-123", DOMAIN, ISSUER));
        assertThat(exception.getCode(), is("authorization_pending"));
        assertThat(exception.isAuthorizationPending(), is(true));
        assertThat(exception.isSlowDown(), is(false));
    }

    @Test
    public void shouldTranslateSlowDownIntoBackChannelException() throws Exception {
        Request<BackChannelTokenResponse> pollRequest = stubPollRequestThatThrows(
                apiException("slow_down", "Polling too fast."));

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);
        when(mockAuthAPI.getBackChannelLoginStatus("auth-req-123", CIBA_GRANT_TYPE)).thenReturn(pollRequest);

        BackChannelAuthorizationException exception = assertThrows(
                BackChannelAuthorizationException.class,
                () -> spy.executeBackChannelPoll("auth-req-123", DOMAIN, ISSUER));
        assertThat(exception.getCode(), is("slow_down"));
        assertThat(exception.isSlowDown(), is(true));
    }

    @Test
    public void shouldTranslateExpiredTokenIntoBackChannelException() throws Exception {
        Request<BackChannelTokenResponse> pollRequest = stubPollRequestThatThrows(
                apiException("expired_token", "The auth_req_id expired."));

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);
        when(mockAuthAPI.getBackChannelLoginStatus("auth-req-123", CIBA_GRANT_TYPE)).thenReturn(pollRequest);

        BackChannelAuthorizationException exception = assertThrows(
                BackChannelAuthorizationException.class,
                () -> spy.executeBackChannelPoll("auth-req-123", DOMAIN, ISSUER));
        assertThat(exception.getCode(), is("expired_token"));
        assertThat(exception.isExpiredToken(), is(true));
    }

    @Test
    public void shouldTranslateAccessDeniedIntoBackChannelException() throws Exception {
        Request<BackChannelTokenResponse> pollRequest = stubPollRequestThatThrows(
                apiException("access_denied", "The user rejected the request."));

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);
        when(mockAuthAPI.getBackChannelLoginStatus("auth-req-123", CIBA_GRANT_TYPE)).thenReturn(pollRequest);

        BackChannelAuthorizationException exception = assertThrows(
                BackChannelAuthorizationException.class,
                () -> spy.executeBackChannelPoll("auth-req-123", DOMAIN, ISSUER));
        assertThat(exception.getCode(), is("access_denied"));
        assertThat(exception.isAccessDenied(), is(true));
    }

    @Test
    public void shouldThrowMissingIdTokenWhenPollResponseHasNoIdToken() throws Exception {
        BackChannelTokenResponse body = mock(BackChannelTokenResponse.class);
        when(body.getIdToken()).thenReturn(null);
        Request<BackChannelTokenResponse> pollRequest = stubPollRequestReturning(body);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);
        when(mockAuthAPI.getBackChannelLoginStatus("auth-req-123", CIBA_GRANT_TYPE)).thenReturn(pollRequest);

        InvalidRequestException exception = assertThrows(
                InvalidRequestException.class,
                () -> spy.executeBackChannelPoll("auth-req-123", DOMAIN, ISSUER));
        assertThat(exception.getCode(), is("a0.missing_id_token"));
    }

    @Test
    public void shouldThrowWhenPollIdTokenVerificationFails() throws Exception {
        // Structurally valid JWT with an invalid signature so verification fails.
        String fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3dyb25nLyIsInN1YiI6InVzZXIxMjMiLCJhdWQiOiJ0ZXN0Q2xpZW50SWQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMH0.signature";
        BackChannelTokenResponse body = mock(BackChannelTokenResponse.class);
        when(body.getIdToken()).thenReturn(fakeJwt);
        Request<BackChannelTokenResponse> pollRequest = stubPollRequestReturning(body);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);
        when(mockAuthAPI.getBackChannelLoginStatus("auth-req-123", CIBA_GRANT_TYPE)).thenReturn(pollRequest);

        IdentityVerificationException exception = assertThrows(
                IdentityVerificationException.class,
                () -> spy.executeBackChannelPoll("auth-req-123", DOMAIN, ISSUER));
        assertThat(exception.getCode(), is("a0.invalid_jwt_error"));
    }

    @Test
    public void shouldReturnVerifiedTokensOnSuccessfulPoll() throws Exception {
        String idToken = signedIdToken(null);
        BackChannelTokenResponse body = mock(BackChannelTokenResponse.class);
        when(body.getIdToken()).thenReturn(idToken);
        when(body.getAccessToken()).thenReturn("cibaAccessToken");
        when(body.getExpiresIn()).thenReturn(86400L);
        when(body.getScope()).thenReturn("openid profile");
        Request<BackChannelTokenResponse> pollRequest = stubPollRequestReturning(body);

        RequestProcessor spy = spy(createDefaultRequestProcessor());
        doReturn(mockAuthAPI).when(spy).createClientForDomain(DOMAIN);
        when(mockAuthAPI.getBackChannelLoginStatus("auth-req-123", CIBA_GRANT_TYPE)).thenReturn(pollRequest);

        Tokens tokens = spy.executeBackChannelPoll("auth-req-123", DOMAIN, ISSUER);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getIdToken(), is(idToken));
        assertThat(tokens.getAccessToken(), is("cibaAccessToken"));
        assertThat(tokens.getType(), is("Bearer"));
        assertThat(tokens.getExpiresIn(), is(86400L));
        assertThat(tokens.getScope(), is("openid profile"));
        // CIBA never returns a refresh token.
        assertThat(tokens.getRefreshToken(), is(nullValue()));
    }

    // --- Logging and Telemetry Tests ---

    @Test
    public void shouldSetLoggingEnabled() {
        RequestProcessor processor = createDefaultRequestProcessor();

        processor.setLoggingEnabled(true);

        AuthAPI client = processor.createClientForDomain(DOMAIN);
        assertThat(client, is(notNullValue()));
    }

    @Test
    public void shouldDisableTelemetry() {
        RequestProcessor processor = createDefaultRequestProcessor();

        processor.doNotSendTelemetry();

        AuthAPI client = processor.createClientForDomain(DOMAIN);
        assertThat(client, is(notNullValue()));
    }

    // --- Response Type Parsing Tests ---

    @Test
    public void shouldParseResponseTypeCode() {
        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_CODE);

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Collections.singletonList("code")));
    }

    @Test
    public void shouldParseResponseTypeToken() {
        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_TOKEN);

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Collections.singletonList("token")));
    }

    @Test
    public void shouldParseResponseTypeIdToken() {
        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_ID_TOKEN);

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Collections.singletonList("id_token")));
    }

    @Test
    public void shouldParseMultipleResponseTypes() {
        RequestProcessor processor = createRequestProcessorWithResponseType("code id_token token");

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Arrays.asList("code", "id_token", "token")));
    }

    // --- Form Post Response Mode Tests ---

    @Test
    public void shouldRequireFormPostForImplicitGrant() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(
                Arrays.asList("id_token", "token"));

        assertThat(requiresFormPost, is(true));
    }

    @Test
    public void shouldNotRequireFormPostForCodeGrant() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(
                Collections.singletonList("code"));

        assertThat(requiresFormPost, is(false));
    }

    @Test
    public void shouldRequireFormPostForHybridFlow() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(
                Arrays.asList("code", "id_token"));

        assertThat(requiresFormPost, is(true));
    }

    @Test
    public void shouldNotRequireFormPostForNullResponseType() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(null);

        assertThat(requiresFormPost, is(false));
    }

    // --- Error Handling Tests ---

    @Test
    public void shouldThrowOnProcessIfRequestHasError() {
        request.setParameter("error", "access_denied");
        request.setParameter("error_description", "The user denied the request");

        RequestProcessor processor = createDefaultRequestProcessor();

        InvalidRequestException e = assertThrows(
                InvalidRequestException.class,
                () -> processor.process(request, response));

        assertThat(e.getCode(), is("access_denied"));
        assertThat(e.getMessage(), is("The user denied the request"));
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasErrorWithDescription() {
        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        params.put("error_description", "something happened description");
        MockHttpServletRequest request = getRequest(params);

        RequestProcessor handler = createDefaultRequestProcessor();

        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("something happened"));
        assertThat(e.getMessage(), is("something happened description"));
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasInvalidStateInCookie() {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "9999"));

        RequestProcessor handler = createDefaultRequestProcessor();

        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("a0.invalid_state"));
        assertThat(e.getMessage(), is("The received state doesn't match the expected one."));
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasMissingStateParameter() {
        MockHttpServletRequest request = getRequest(Collections.emptyMap());
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = createDefaultRequestProcessor();

        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("a0.invalid_state"));
        assertThat(e.getMessage(), is("The received state doesn't match the expected one. No state parameter was found on the authorization response."));
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasMissingStateCookie() {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);

        RequestProcessor handler = createDefaultRequestProcessor();

        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("a0.invalid_state"));
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestIsMissingIdToken() {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = createRequestProcessorWithResponseType(RESPONSE_TYPE_ID_TOKEN);

        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("a0.missing_id_token"));
        assertThat(e.getMessage(), is("ID Token is missing from the response."));
    }

    @Test
    public void shouldThrowOnProcessIfTokenRequestIsMissingAccessToken() {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = createRequestProcessorWithResponseType(RESPONSE_TYPE_TOKEN);

        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("a0.missing_access_token"));
        assertThat(e.getMessage(), is("Access Token is missing from the response."));
    }

    // --- Code Exchange Flow Tests ---

    @Test
    public void shouldThrowOnProcessIfCodeRequestFailsToExecuteCodeExchange() throws Exception {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        when(mockTokenRequest.execute()).thenThrow(Auth0Exception.class);
        when(mockAuthAPI.exchangeCode(eq("abc123"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> spy.process(request, response));
        assertThat(e.getCode(), is("a0.api_error"));
        assertThat(e.getMessage(), is("An error occurred while exchanging the authorization code."));
    }

    @Test
    public void shouldThrowOnProcessIfCodeRequestSucceedsButDoesNotPassIdTokenVerification() throws Exception {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        // Return a structurally valid JWT with invalid signature so verification fails
        String fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3dyb25nLyIsInN1YiI6InVzZXIxMjMiLCJhdWQiOiJ0ZXN0Q2xpZW50SWQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMH0.signature";
        when(mockTokenHolder.getIdToken()).thenReturn(fakeJwt);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockAuthAPI.exchangeCode(eq("abc123"), anyString())).thenReturn(mockTokenRequest);

        // Use mockJwkProvider — token has invalid signature so RS256 verification will fail
        RequestProcessor handler = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withJwkProvider(mockJwkProvider)
                .build();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> spy.process(request, response));
        assertThat(e.getCode(), is("a0.invalid_jwt_error"));
        assertThat(e.getMessage(), is("An error occurred while trying to verify the ID Token."));
    }

    @Test
    public void shouldReturnTokensOnProcessIfCodeRequestSucceeds() throws Exception {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        // Return no ID token so verification is skipped
        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getAccessToken()).thenReturn("backAccessToken");
        when(mockTokenHolder.getRefreshToken()).thenReturn("backRefreshToken");
        when(mockTokenHolder.getTokenType()).thenReturn("Bearer");
        when(mockTokenHolder.getExpiresIn()).thenReturn(3600L);
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockAuthAPI.exchangeCode(eq("abc123"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        Tokens tokens = spy.process(request, response);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("backAccessToken"));
        assertThat(tokens.getRefreshToken(), is("backRefreshToken"));
        assertThat(tokens.getType(), is("Bearer"));
        assertThat(tokens.getExpiresIn(), is(3600L));
    }

    @Test
    public void shouldReturnEmptyTokensWhenCodeRequestReturnsNoTokens() throws Exception {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockAuthAPI.exchangeCode(eq("abc123"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        Tokens tokens = spy.process(request, response);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getIdToken(), is(nullValue()));
        assertThat(tokens.getAccessToken(), is(nullValue()));
        assertThat(tokens.getRefreshToken(), is(nullValue()));
    }

    // --- Implicit / Hybrid Flow Tests ---

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestDoesNotPassIdTokenVerification() {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        // Structurally valid JWT with invalid signature so verification fails
        String fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3dyb25nLyIsInN1YiI6InVzZXIxMjMiLCJhdWQiOiJ0ZXN0Q2xpZW50SWQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMH0.signature";

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("id_token", fakeJwt);
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        // Use mockJwkProvider — token has invalid signature so RS256 verification will fail
        RequestProcessor handler = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_ID_TOKEN,
                CLIENT_ID,
                CLIENT_SECRET)
                .withJwkProvider(mockJwkProvider)
                .build();

        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("a0.invalid_jwt_error"));
        assertThat(e.getMessage(), is("An error occurred while trying to verify the ID Token."));
    }

    // --- AuthorizeUrl Building Tests ---

    @Test
    public void shouldBuildAuthorizeUrlWithStateAndNonce() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = createDefaultRequestProcessor();
        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
        verify(spy).createClientForDomain(DOMAIN);
    }

    @Test
    public void shouldBuildAuthorizeUrlWithOrganization() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withOrganization("org_123")
                .build();

        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithInvitation() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withInvitation("inv_456")
                .build();

        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithCustomCookiePath() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withCookiePath("/custom")
                .build();

        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithFormPostIfResponseTypeIsToken() {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor handler = createRequestProcessorWithResponseType(RESPONSE_TYPE_TOKEN);
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://redirect.uri/here", "state", "nonce");

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithNonceAndFormPostIfResponseTypeIsIdToken() {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor handler = createRequestProcessorWithResponseType(RESPONSE_TYPE_ID_TOKEN);
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://redirect.uri/here", "state", "nonce");

        assertThat(result, is(notNullValue()));
    }

    // --- Builder Configuration Tests ---

    @Test
    public void shouldSupportOrganizationParameter() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withOrganization("org_123")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportInvitationParameter() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withInvitation("inv_456")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportCustomCookiePath() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withCookiePath("/custom/path")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportClockSkewConfiguration() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withClockSkew(180)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportAuthenticationMaxAge() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withAuthenticationMaxAge(7200)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    // --- Custom HttpClient Tests ---

    @Test
    public void shouldBuildWithCustomHttpClient() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withHttpClient(mockHttpClient)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldCreateClientForDomainWithCustomHttpClient() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withHttpClient(mockHttpClient)
                .build();

        AuthAPI client = processor.createClientForDomain(DOMAIN);
        assertThat(client, is(notNullValue()));
    }

    @Test
    public void shouldReuseCustomHttpClientAcrossMultipleDomains() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withHttpClient(mockHttpClient)
                .build();

        AuthAPI client1 = processor.createClientForDomain("domain1.auth0.com");
        AuthAPI client2 = processor.createClientForDomain("domain2.auth0.com");

        assertThat(client1, is(notNullValue()));
        assertThat(client2, is(notNullValue()));
    }

    @Test
    public void shouldCreateDefaultHttpClientWhenNoneProvided() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .build();

        AuthAPI client = processor.createClientForDomain(DOMAIN);
        assertThat(client, is(notNullValue()));
    }

    @Test
    public void shouldReuseDefaultHttpClientAcrossMultipleCalls() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .build();

        AuthAPI client1 = processor.createClientForDomain("domain1.auth0.com");
        AuthAPI client2 = processor.createClientForDomain("domain2.auth0.com");

        assertThat(client1, is(notNullValue()));
        assertThat(client2, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithHttpClientAndJwkProvider() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withHttpClient(mockHttpClient)
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    // --- Transaction-Keyed Cookie Tests ---

    @Test
    public void shouldValidateStateFromTransactionKeyedCookie() {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("state", "txn-state-123");
        params.put("code", "auth-code");
        MockHttpServletRequest request = getRequest(params);
        // Transaction-keyed cookie: com.auth0.state.{state_value}
        request.setCookies(new Cookie("com.auth0.state.txn-state-123", "txn-state-123"));

        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getAccessToken()).thenReturn("access");
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        try {
            when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        } catch (Auth0Exception e) {
            fail("Unexpected exception");
        }
        when(mockAuthAPI.exchangeCode(eq("auth-code"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        assertDoesNotThrow(() -> spy.process(request, response));
    }

    @Test
    public void shouldFallbackToLegacyStateCookieWhenTransactionKeyedMissing() {
        when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);

        Map<String, Object> params = new HashMap<>();
        params.put("state", "legacy-state-456");
        params.put("code", "auth-code");
        MockHttpServletRequest request = getRequest(params);
        // Legacy fixed-name cookie (v1 compatibility)
        request.setCookies(new Cookie("com.auth0.state", "legacy-state-456"));

        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getAccessToken()).thenReturn("access");
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        try {
            when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        } catch (Auth0Exception e) {
            fail("Unexpected exception");
        }
        when(mockAuthAPI.exchangeCode(eq("auth-code"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        assertDoesNotThrow(() -> spy.process(request, response));
    }

    @Test
    public void shouldRejectWhenNoStateCookieExists() {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "orphan-state");
        MockHttpServletRequest request = getRequest(params);
        // No cookies at all

        RequestProcessor handler = createDefaultRequestProcessor();

        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e.getCode(), is("a0.invalid_state"));
    }

    // --- MCD Origin Domain Binding Tests ---

    @Test
    public void shouldUseDomainFromSignedCookieWhenPresent() throws Exception {
        String state = "mcd-state-789";
        String domain = "brand-a.auth0.com";

        // Create a signed origin domain cookie
        String signedDomain = SignedCookieUtils.sign(domain, state, CLIENT_SECRET);

        Map<String, Object> params = new HashMap<>();
        params.put("state", state);
        params.put("code", "auth-code");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(
                new Cookie("com.auth0.state." + state, state),
                new Cookie("com.auth0.origin_domain", signedDomain)
        );

        when(mockDomainProvider.getDomain(any())).thenReturn("fallback.auth0.com");
        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getAccessToken()).thenReturn("access");
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockAuthAPI.exchangeCode(eq("auth-code"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        spy.process(request, response);

        // Should use the domain from the signed cookie, not the fallback
        verify(spy).createClientForDomain(domain);
    }

    @Test
    public void shouldFallbackToDomainProviderWhenSignedCookieMissing() throws Exception {
        String state = "no-cookie-state";
        String fallbackDomain = "fallback.auth0.com";

        Map<String, Object> params = new HashMap<>();
        params.put("state", state);
        params.put("code", "auth-code");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state." + state, state));

        when(mockDomainProvider.getDomain(any())).thenReturn(fallbackDomain);
        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getAccessToken()).thenReturn("access");
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockAuthAPI.exchangeCode(eq("auth-code"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        spy.process(request, response);

        // Should fall back to domainProvider when no signed origin cookie
        verify(spy).createClientForDomain(fallbackDomain);
    }

    @Test
    public void shouldFallbackToDomainProviderWhenSignedCookieTampered() throws Exception {
        String state = "tampered-state";
        String fallbackDomain = "fallback.auth0.com";

        // Tampered cookie — signed with different state
        String signedDomain = SignedCookieUtils.sign("evil.auth0.com", "different-state", CLIENT_SECRET);

        Map<String, Object> params = new HashMap<>();
        params.put("state", state);
        params.put("code", "auth-code");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(
                new Cookie("com.auth0.state." + state, state),
                new Cookie("com.auth0.origin_domain", signedDomain)
        );

        when(mockDomainProvider.getDomain(any())).thenReturn(fallbackDomain);
        when(mockTokenHolder.getIdToken()).thenReturn(null);
        when(mockTokenHolder.getAccessToken()).thenReturn("access");
        when(mockTokenResponse.getBody()).thenReturn(mockTokenHolder);
        when(mockTokenRequest.execute()).thenReturn(mockTokenResponse);
        when(mockAuthAPI.exchangeCode(eq("auth-code"), anyString())).thenReturn(mockTokenRequest);

        RequestProcessor handler = createDefaultRequestProcessor();
        RequestProcessor spy = spy(handler);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        spy.process(request, response);

        // Tampered cookie should be rejected, fallback to domainProvider
        verify(spy).createClientForDomain(fallbackDomain);
    }

    // --- Helper Methods ---

    private static final String CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba";

    // Builds an APIException carrying the given OAuth error code and description, matching the
    // wire shape Auth0 returns for a failed CIBA poll (400 with error/error_description).
    private APIException apiException(String error, String description) {
        Map<String, Object> body = new HashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        return new APIException(body, 400);
    }

    @SuppressWarnings("unchecked")
    private Request<BackChannelTokenResponse> stubPollRequestThatThrows(APIException e) throws Exception {
        Request<BackChannelTokenResponse> pollRequest = mock(Request.class);
        when(pollRequest.execute()).thenThrow(e);
        return pollRequest;
    }

    @SuppressWarnings("unchecked")
    private Request<BackChannelTokenResponse> stubPollRequestReturning(BackChannelTokenResponse body) throws Exception {
        Request<BackChannelTokenResponse> pollRequest = mock(Request.class);
        Response<BackChannelTokenResponse> pollResponse = mock(Response.class);
        when(pollRequest.execute()).thenReturn(pollResponse);
        when(pollResponse.getBody()).thenReturn(body);
        return pollRequest;
    }

    // Builds an HS256 ID token signed with CLIENT_SECRET so the RS256/HS256-aware verifier accepts
    // it (HS256 path uses the client secret). Pass a non-null orgId to include an org_id claim.
    private String signedIdToken(String orgId) {
        JWTCreator.Builder builder = JWT.create()
                .withIssuer(ISSUER)
                .withSubject("user123")
                .withAudience(CLIENT_ID)
                .withIssuedAt(new Date(System.currentTimeMillis() - 1000))
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600_000));
        if (orgId != null) {
            builder.withClaim("org_id", orgId);
        }
        return builder.sign(Algorithm.HMAC256(CLIENT_SECRET));
    }

    private RequestProcessor createDefaultRequestProcessor() {
        return new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET)
                .withJwkProvider(mockJwkProvider)
                .build();
    }

    private RequestProcessor createRequestProcessorWithResponseType(String responseType) {
        return new RequestProcessor.Builder(
                mockDomainProvider,
                responseType,
                CLIENT_ID,
                CLIENT_SECRET)
                .withJwkProvider(mockJwkProvider)
                .build();
    }

    private MockHttpServletRequest getRequest(Map<String, Object> parameters) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("me.auth0.com");
        request.setServerPort(80);
        request.setRequestURI("/callback");
        request.setParameters(parameters);
        return request;
    }
}
