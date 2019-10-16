package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwt.exceptions.JWTVerificationException;
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
        exception.expectMessage("The request contains an error: something happened");

        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasInvalidState() throws Exception {
        exception.expect(InvalidRequestException.class);
        exception.expectMessage("The request contains an error: a0.invalid_state");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "9999");

        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestIsMissingIdToken() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expectMessage("Id Token is missing from the response.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        RequestProcessor handler = new RequestProcessor(client, "id_token", verifyOptions);
        handler.process(req);
    }

    @Test
    public void shouldThrowOnProcessIfTokenRequestIsMissingAccessToken() throws Exception {
        exception.expect(IdentityVerificationException.class);
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
        exception.expectMessage("An error occurred while trying to verify the Id Token.");

        doThrow(JWTVerificationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

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
        exception.expectMessage("An error occurred while trying to verify the Id Token.");

        doThrow(JWTVerificationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

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
        exception.expectMessage("An error occurred while exchanging the Authorization Code for Auth0 Tokens.");


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
        exception.expectMessage("An error occurred while trying to verify the Id Token.");

        doThrow(JWTVerificationException.class).when(tokenVerifier).verify(eq("backIdToken"), eq(verifyOptions));

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
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        AuthRequest codeExchangeRequest = mock(AuthRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
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
    }


    //Implicit Grant

//    @Test
//    public void shouldThrowOnMissingCodeAndImplicitGrantNotAllowed() throws Exception {
//        exception.expect(InvalidRequestException.class);
//        exception.expectMessage("The request contains an error: a0.missing_authorization_code");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//
//        RequestProcessor handler = new RequestProcessor(client, "code", verifyOptions, tokenVerifier);
//        handler.process(req);
//    }


    //    @Test
//    public void shouldVerifyIdTokenOnImplicitGrant() throws Exception {
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        RandomStorage.setSessionNonce(req, "nnnccc");
//
//        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifyOptions);
//        Tokens tokens = handler.process(req);
//
//        verify(client, never()).userInfo(anyString());
//        assertThat(tokens, is(notNullValue()));
//        assertThat(tokens.getAccessToken(), is("theAccessToken"));
//        assertThat(tokens.getIdToken(), is("theIdToken"));
//    }
//
//    @Test
//    public void shouldThrowOnFailToVerifyIdTokenOnImplicitGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
//        exception.expectMessage("An error occurred while trying to verify the Id Token.");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        RandomStorage.setSessionNonce(req, "nnnccc");
//        doThrow(JWTVerificationException.class).when(signatureVerifier).verifySignature("theIdToken");
//
//        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifyOptions);
//        handler.process(req);
//
//        verify(client, never()).userInfo(anyString());
//    }
//
//    @Test
//    public void shouldThrowOnFailToGetPublicKeyOnImplicitGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.missing_jwt_public_key_error"));
//        exception.expectMessage("An error occurred while trying to verify the Id Token.");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        RandomStorage.setSessionNonce(req, "nnnccc");
//        doThrow(JwkException.class).when(signatureVerifier).verifySignature("theIdToken");
//
//        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifyOptions);
//        handler.process(req);
//
//        verify(client, never()).userInfo(anyString());
//    }
//
//    @Test
//    public void shouldThrowIfNullUserIdOnVerifyIdTokenOnImplicitGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.unknown_error"));
//        exception.expectMessage("An error occurred while trying to verify the user identity: The 'sub' claim contained in the token was null.");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//
//        doNothing().when(signatureVerifier).verifySignature("theIdToken");
//
//        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifyOptions);
//        handler.process(req);
//
//
//        verify(client, never()).userInfo(anyString());
//    }
//
//    @Test
//    public void shouldVerifyAccessTokenOnImplicitGrant() throws Exception {
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);
//
//        RequestProcessor handler = new RequestProcessor(client, "token", verifyOptions);
//        Tokens tokens = handler.process(req);
//
//        verifyNoMoreInteractions(signatureVerifier);
//        verify(client).userInfo("theAccessToken");
//        assertThat(tokens, is(notNullValue()));
//        assertThat(tokens.getAccessToken(), is("theAccessToken"));
//        assertThat(tokens.getIdToken(), is(nullValue()));
//    }
//
//    @Test
//    public void shouldThrowOnFailToVerifyAccessTokenOnImplicitGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.api_error"));
//        exception.expectMessage("An error occurred while trying to verify the Access Token.");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        when(client.userInfo("theAccessToken")).thenThrow(Auth0Exception.class);
//
//        RequestProcessor handler = new RequestProcessor(client, "token", verifyOptions);
//        handler.process(req);
//
//        verifyNoMoreInteractions(signatureVerifier);
//        verify(client, never()).userInfo(anyString());
//    }
//
//    @Test
//    public void shouldThrowIfNullUserIdOnFailToVerifyAccessTokenOnImplicitGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.unknown_error"));
//        exception.expectMessage("An error occurred while trying to verify the user identity: The 'sub' claim contained in the token was null.");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        Request userInfoRequest = mock(Request.class);
//        when(userInfo.getValues()).thenReturn(Collections.<String, Object>emptyMap());
//        when(userInfoRequest.execute()).thenReturn(userInfo);
//        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);
//
//        RequestProcessor handler = new RequestProcessor(client, "token", verifyOptions);
//        handler.process(req);
//
//        verifyNoMoreInteractions(signatureVerifier);
//        verify(client, never()).userInfo(anyString());
//    }
//
//    //Code Grant
//
//
//    @Test
//    public void shouldFetchUserIdUsingAccessTokenOnCodeGrant() throws Exception {
//        Map<String, Object> params = new HashMap<>();
//        params.put("code", "abc123");
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
//        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);
//
//        RequestProcessor handler = new RequestProcessor(client, "code", null);
//        Tokens tokens = handler.process(req);
//        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
//        verify(client).userInfo("theAccessToken");
//
//        assertThat(tokens, is(notNullValue()));
//        assertThat(tokens.getAccessToken(), is("theAccessToken"));
//        assertThat(tokens.getIdToken(), is("theIdToken"));
//    }
//
//    @Test
//    public void shouldFetchUserIdUsingTheBestAccessTokenOnCodeGrant() throws Exception {
//        Map<String, Object> params = new HashMap<>();
//        params.put("code", "abc123");
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
//        TokenHolder holder = mock(TokenHolder.class);
//        when(holder.getAccessToken()).thenReturn("theBestAccessToken");
//        when(codeExchangeRequest.execute()).thenReturn(holder);
//        when(client.userInfo("theBestAccessToken")).thenReturn(userInfoRequest);
//
//        RequestProcessor handler = new RequestProcessor(client, "code", null);
//        Tokens tokens = handler.process(req);
//        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
//        verify(client).userInfo("theBestAccessToken");
//
//        assertThat(tokens, is(notNullValue()));
//        assertThat(tokens.getAccessToken(), is("theBestAccessToken"));
//        assertThat(tokens.getIdToken(), is("theIdToken"));
//    }
//
//    @Test
//    public void shouldThrowOnExchangeTheAuthorizationCodeOnCodeGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.api_error"));
//        exception.expectMessage("An error occurred while exchanging the Authorization Code for Auth0 Tokens.");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("code", "abc123");
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenThrow(Auth0Exception.class);
//
//        RequestProcessor handler = new RequestProcessor(client, "code", null);
//        handler.process(req);
//        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
//    }
//
//    @Test
//    public void shouldThrowOnFetchTheUserIdOnCodeGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.api_error"));
//        exception.expectMessage("An error occurred while exchanging the Authorization Code for Auth0 Tokens.");
//
//        Map<String, Object> params = new HashMap<>();
//        params.put("code", "abc123");
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//
//        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
//        when(client.userInfo("theAccessToken")).thenThrow(Auth0Exception.class);
//
//        RequestProcessor handler = new RequestProcessor(client, "code", null);
//        handler.process(req);
//        verify(client).userInfo("theAccessToken");
//    }
//
//    @Test
//    public void shouldFailToGetTheUserIdOnCodeGrant() throws Exception {
//        exception.expect(IdentityVerificationException.class);
//        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.unknown_error"));
//        exception.expectMessage("An error occurred while trying to verify the user identity: The 'sub' claim contained in the token was null.");
//        Map<String, Object> params = new HashMap<>();
//        params.put("code", "abc123");
//        params.put("state", "1234");
//        params.put("access_token", "theAccessToken");
//        params.put("id_token", "theIdToken");
//        HttpServletRequest req = getRequest(params);
//        RandomStorage.setSessionState(req, "1234");
//        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
//        when(userInfo.getValues()).thenReturn(Collections.<String, Object>emptyMap());
//        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);
//
//        RequestProcessor handler = new RequestProcessor(client, "code", null);
//        handler.process(req);
//        verify(client).userInfo("theAccessToken");
//    }

    @Test
    public void shouldBuildAuthorizeUrl() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
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
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
        assertThat(authorizeUrl, not(containsString("response_mode=form_post")));
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