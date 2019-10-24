package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.AuthRequest;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.*;

public class RequestProcessorTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private AuthAPI client;
    @Mock
    private IdTokenVerifier.Options verifyOptions;
    @Mock
    private IdTokenVerifier tokenVerifier;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldThrowOnMissingAuthAPI() {
        exception.expect(NullPointerException.class);
        new RequestProcessor(null, "responseType", verifyOptions);
    }

    @Test
    public void shouldThrowOnMissingResponseType() {
        exception.expect(NullPointerException.class);
        new RequestProcessor(client, null, verifyOptions);
    }

    @Test
    public void shouldNotThrowOnMissingTokenVerifierOptions() {
        exception.expect(NullPointerException.class);
        new RequestProcessor(client, "responseType", null);
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasError() throws Exception {
        exception.expect(InvalidRequestException.class);
        exception.expect(InvalidRequestExceptionMatcher.hasCode("something happened"));
        exception.expect(InvalidRequestExceptionMatcher.hasDescription("The request contains an error"));
        exception.expectMessage("The request contains an error");

        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasInvalidState() throws Exception {
        exception.expect(InvalidRequestException.class);
        exception.expect(InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        exception.expect(InvalidRequestExceptionMatcher.hasDescription("The received state doesn't match the expected one."));
        exception.expectMessage("The received state doesn't match the expected one.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "9999");

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestIsMissingIdToken() throws Exception {
        exception.expect(InvalidRequestException.class);
        exception.expect(InvalidRequestExceptionMatcher.hasCode("a0.missing_id_token"));
        exception.expect(InvalidRequestExceptionMatcher.hasDescription("ID Token is missing from the response."));
        exception.expectMessage("ID Token is missing from the response.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(client, "id_token", verifyOptions);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfTokenRequestIsMissingAccessToken() throws Exception {
        exception.expect(InvalidRequestException.class);
        exception.expect(InvalidRequestExceptionMatcher.hasCode("a0.missing_access_token"));
        exception.expect(InvalidRequestExceptionMatcher.hasDescription("Access Token is missing from the response."));
        exception.expectMessage("Access Token is missing from the response.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(client, "token", verifyOptions);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestDoesNotPassIdTokenVerification() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        exception.expectMessage("An error occurred while trying to verify the ID Token.");

        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(client, "id_token", verifyOptions, tokenVerifier);
        handler.process(req);
    }

    @Test
    public void shouldReturnTokensOnProcessIfIdTokenRequestPassesIdTokenVerification() throws Exception {
        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(client, "id_token", verifyOptions, tokenVerifier);
        Tokens process = handler.process(req);
        assertThat(process, is(notNullValue()));
        assertThat(process.getIdToken(), is("frontIdToken"));
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenCodeRequestDoesNotPassIdTokenVerification() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        exception.expectMessage("An error occurred while trying to verify the ID Token.");

        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(client, "id_token code", verifyOptions, tokenVerifier);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfCodeRequestFailsToExecuteCodeExchange() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.api_error"));
        exception.expectMessage("An error occurred while exchanging the authorization code.");


        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        AuthRequest codeExchangeRequest = mock(AuthRequest.class);
        when(codeExchangeRequest.execute()).thenThrow(Auth0Exception.class);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions, tokenVerifier);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfCodeRequestSucceedsButDoesNotPassIdTokenVerification() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        exception.expectMessage("An error occurred while trying to verify the ID Token.");

        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("backIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        AuthRequest codeExchangeRequest = mock(AuthRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions, tokenVerifier);
        handler.process(req);
    }

    @Test
    public void shouldReturnTokensOnProcessIfIdTokenCodeRequestPassesIdTokenVerification() throws Exception {
        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        params.put("expires_in", "8400");
        params.put("token_type", "frontTokenType");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        AuthRequest codeExchangeRequest = mock(AuthRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor(client, "id_token code", verifyOptions, tokenVerifier);
        Tokens tokens = handler.process(req);

        //Should not verify the ID Token twice
        verify(tokenVerifier).verify("frontIdToken", verifyOptions);
        verify(tokenVerifier, never()).verify("backIdToken", verifyOptions);
        verifyNoMoreInteractions(tokenVerifier);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getIdToken(), is("frontIdToken"));
        assertThat(tokens.getType(), is("frontTokenType"));
        assertThat(tokens.getExpiresIn(), is(8400L));
    }

    @Test
    public void shouldReturnTokensOnProcessIfTokenIdTokenCodeRequestPassesIdTokenVerification() throws Exception {
        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        params.put("access_token", "frontAccessToken");
        params.put("expires_in", "8400");
        params.put("token_type", "frontTokenType");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        AuthRequest codeExchangeRequest = mock(AuthRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getAccessToken()).thenReturn("backAccessToken");
        when(tokenHolder.getRefreshToken()).thenReturn("backRefreshToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor(client, "id_token token code", verifyOptions, tokenVerifier);
        Tokens tokens = handler.process(req);

        //Should not verify the ID Token twice
        verify(tokenVerifier).verify("frontIdToken", verifyOptions);
        verify(tokenVerifier, never()).verify("backIdToken", verifyOptions);
        verifyNoMoreInteractions(tokenVerifier);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getIdToken(), is("frontIdToken"));
        assertThat(tokens.getAccessToken(), is("backAccessToken"));
        assertThat(tokens.getRefreshToken(), is("backRefreshToken"));
        assertThat(tokens.getExpiresIn(), is(4800L));
        assertThat(tokens.getType(), is("backTokenType"));
    }

    @Test
    public void shouldReturnTokensOnProcessIfCodeRequestPassesIdTokenVerification() throws Exception {
        doNothing().when(tokenVerifier).verify(eq("backIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        AuthRequest codeExchangeRequest = mock(AuthRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getAccessToken()).thenReturn("backAccessToken");
        when(tokenHolder.getRefreshToken()).thenReturn("backRefreshToken");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions, tokenVerifier);
        Tokens tokens = handler.process(req);

        verify(tokenVerifier).verify("backIdToken", verifyOptions);
        verifyNoMoreInteractions(tokenVerifier);

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getIdToken(), is("backIdToken"));
        assertThat(tokens.getAccessToken(), is("backAccessToken"));
        assertThat(tokens.getRefreshToken(), is("backRefreshToken"));
    }

    @Test
    public void shouldReturnEmptyTokensWhenCodeRequestReturnsNoTokens() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        AuthRequest codeExchangeRequest = mock(AuthRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions, tokenVerifier);
        Tokens tokens = handler.process(req);

        verifyNoMoreInteractions(tokenVerifier);

        assertThat(tokens, is(notNullValue()));

        assertThat(tokens.getIdToken(), is(nullValue()));
        assertThat(tokens.getAccessToken(), is(nullValue()));
        assertThat(tokens.getRefreshToken(), is(nullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrl() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
        IdTokenVerifier.Options verifyOptions = new IdTokenVerifier.Options("issuer", "audience", signatureVerifier);
        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https://redirect.uri/here"));
        assertThat(authorizeUrl, containsString("response_type=code"));
        assertThat(authorizeUrl, containsString("scope=openid"));
        assertThat(authorizeUrl, containsString("state=state"));
        assertThat(authorizeUrl, not(containsString("max_age=")));
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
        assertThat(authorizeUrl, not(containsString("response_mode=form_post")));
    }

    @Test
    public void shouldSetMaxAgeIfProvided() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        when(verifyOptions.getMaxAge()).thenReturn(906030);
        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, containsString("max_age=906030"));
    }

    @Test
    public void shouldNotSetNonceIfRequestTypeIsNotIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
    }

    @Test
    public void shouldSetNonceIfRequestTypeIsIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "id_token", verifyOptions);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, containsString("nonce=nonce"));
    }

    @Test
    public void shouldNotSetNullNonceIfRequestTypeIsIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "id_token", verifyOptions);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", null);
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithNonceAndFormPostIfResponseTypeIsIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "id_token", verifyOptions);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https://redirect.uri/here"));
        assertThat(authorizeUrl, containsString("response_type=id_token"));
        assertThat(authorizeUrl, containsString("scope=openid"));
        assertThat(authorizeUrl, containsString("state=state"));
        assertThat(authorizeUrl, containsString("nonce=nonce"));
        assertThat(authorizeUrl, containsString("response_mode=form_post"));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithFormPostIfResponseTypeIsToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "token", verifyOptions);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https://redirect.uri/here"));
        assertThat(authorizeUrl, containsString("response_type=token"));
        assertThat(authorizeUrl, containsString("scope=openid"));
        assertThat(authorizeUrl, containsString("state=state"));
        assertThat(authorizeUrl, containsString("response_mode=form_post"));
    }

    @Test
    public void shouldGetAuthAPIClient() {
        RequestProcessor handler = new RequestProcessor(client, "responseType", verifyOptions);
        assertThat(handler.getClient(), is(client));
    }

    // Utils

    private HttpServletRequest getRequest(Map<String, Object> parameters) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("me.auth0.com");
        request.setServerPort(80);
        request.setRequestURI("/callback");
        request.setParameters(parameters);
        return request;
    }
}