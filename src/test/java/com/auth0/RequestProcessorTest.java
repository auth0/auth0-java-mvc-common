package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.TokenRequest;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

public class RequestProcessorTest {

    @Mock
    private AuthAPI client;
    @Mock
    private IdTokenVerifier.Options verifyOptions;
    @Mock
    private IdTokenVerifier tokenVerifier;

    private MockHttpServletResponse response;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        response = new MockHttpServletResponse();
    }

    @Test
    public void shouldThrowOnMissingAuthAPI() {
        assertThrows(NullPointerException.class, () -> new RequestProcessor.Builder(null, "responseType", verifyOptions));
    }

    @Test
    public void shouldThrowOnMissingResponseType() {
        assertThrows(NullPointerException.class, () -> new RequestProcessor.Builder(client, null, verifyOptions));
    }

    @Test
    public void shouldNotThrowOnMissingTokenVerifierOptions() {
        assertThrows(NullPointerException.class, () -> new RequestProcessor.Builder(client, "responseType", null));
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasError() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest request = getRequest(params);

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("something happened"));
        assertEquals("The request contains an error", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasInvalidState() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "9999"));;

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasInvalidStateInSession() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.getSession().setAttribute("com.auth0.state", "9999");

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasMissingStateParameter() throws Exception {
        MockHttpServletRequest request = getRequest(Collections.emptyMap());
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasMissingStateCookie() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestIsMissingIdToken() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.missing_id_token"));
        assertEquals("ID Token is missing from the response.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfTokenRequestIsMissingAccessToken() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = new RequestProcessor.Builder(client, "token", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.missing_access_token"));
        assertEquals("Access Token is missing from the response.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestDoesNotPassIdTokenVerification() throws Exception {
        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e, IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        assertEquals("An error occurred while trying to verify the ID Token.", e.getMessage());
    }

    @Test
    public void shouldReturnTokensOnProcessIfIdTokenRequestPassesIdTokenVerification() throws Exception {
        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"), new Cookie("com.auth0.nonce", "5678"));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        Tokens process = handler.process(request, response);
        assertThat(process, is(notNullValue()));
        assertThat(process.getIdToken(), is("frontIdToken"));
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenCodeRequestDoesNotPassIdTokenVerification() throws Exception {
        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("id_token", "frontIdToken");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e, IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        assertEquals("An error occurred while trying to verify the ID Token.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfCodeRequestFailsToExecuteCodeExchange() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        when(codeExchangeRequest.execute()).thenThrow(Auth0Exception.class);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e, IdentityVerificationExceptionMatcher.hasCode("a0.api_error"));
        assertEquals("An error occurred while exchanging the authorization code.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfCodeRequestSucceedsButDoesNotPassIdTokenVerification() throws Exception {
        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("backIdToken"), eq(verifyOptions));

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e, IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        assertEquals("An error occurred while trying to verify the ID Token.", e.getMessage());

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
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        Tokens tokens = handler.process(request, response);

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
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getAccessToken()).thenReturn("backAccessToken");
        when(tokenHolder.getRefreshToken()).thenReturn("backRefreshToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token token code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        Tokens tokens = handler.process(request, response);

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
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getAccessToken()).thenReturn("backAccessToken");
        when(tokenHolder.getRefreshToken()).thenReturn("backRefreshToken");
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        Tokens tokens = handler.process(request, response);

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
        MockHttpServletRequest request = getRequest(params);
        request.setCookies(new Cookie("com.auth0.state", "1234"));

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(codeExchangeRequest.execute()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        Tokens tokens = handler.process(request, response);

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
        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", "nonce");
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
        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, containsString("max_age=906030"));
    }

    @Test
    public void shouldNotSetNonceIfRequestTypeIsNotIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
    }

    @Test
    public void shouldSetNonceIfRequestTypeIsIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, containsString("nonce=nonce"));
    }

    @Test
    public void shouldNotSetNullNonceIfRequestTypeIsIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", null);
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithNonceAndFormPostIfResponseTypeIsIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", "nonce");
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
        RequestProcessor handler = new RequestProcessor.Builder(client, "token", verifyOptions)
                .build();
        HttpServletRequest request = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response, "https://redirect.uri/here", "state", "nonce");
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
    public void isFormPostReturnsFalseWhenResponseTypeIsNull() {
        assertThat(RequestProcessor.requiresFormPostResponseMode(null), is(false));
    }

    @Test
    public void shouldGetAuthAPIClient() {
        RequestProcessor handler = new RequestProcessor.Builder(client, "responseType", verifyOptions)
                .build();
        assertThat(handler.getClient(), is(client));
    }

    @Test
    public void legacySameSiteCookieShouldBeFalseByDefault() {
        RequestProcessor processor = new RequestProcessor.Builder(client, "responseType", verifyOptions)
                .build();
        assertThat(processor.useLegacySameSiteCookie, is(true));
    }

    // Utils

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
