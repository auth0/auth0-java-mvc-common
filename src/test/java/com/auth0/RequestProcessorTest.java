package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.net.AuthRequest;
import com.auth0.net.Request;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
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
    private TokenVerifier verifier;
    @Mock
    private Request<UserInfo> userInfoRequest;
    @Mock
    private UserInfo userInfo;
    @Mock
    private AuthRequest codeExchangeRequest;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(userInfoRequest.execute()).thenReturn(userInfo);
        when(userInfo.getValues()).thenReturn(Collections.<String, Object>singletonMap("sub", "auth0|user123"));
        TokenHolder holder = mock(TokenHolder.class);
        when(codeExchangeRequest.execute()).thenReturn(holder);
    }

    @Test
    public void shouldThrowOnMissingAuthAPI() throws Exception {
        exception.expect(NullPointerException.class);
        new RequestProcessor(null, "responseType", verifier);
    }

    @Test
    public void shouldThrowOnMissingResponseType() throws Exception {
        exception.expect(NullPointerException.class);
        new RequestProcessor(client, null, verifier);
    }

    @Test
    public void shouldThrowOnMissingTokenVerifier() throws Exception {
        exception.expect(NullPointerException.class);
        new RequestProcessor(client, "responseType", null);
    }

    @Test
    public void shouldThrowIfRequestHasError() throws Exception {
        exception.expect(InvalidRequestException.class);
        exception.expectMessage("The request contains an error: something happened");

        Map<String, Object> params = new HashMap<>();
        params.put("error", "something happened");
        HttpServletRequest req = getRequest(params);

        RequestProcessor handler = new RequestProcessor(client, "responseType", verifier);
        handler.process(req);
    }

    @Test
    public void shouldThrowIfRequestHasInvalidState() throws Exception {
        exception.expect(InvalidRequestException.class);
        exception.expectMessage("The request contains an error: a0.invalid_state");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "9999");

        RequestProcessor handler = new RequestProcessor(client, "responseType", verifier);
        handler.process(req);
    }

    @Test
    public void shouldVerifyIdTokenWhenPresent() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        RandomStorage.setSessionNonce(req, "nnnccc");

        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifier);
        Tokens tokens = handler.process(req);

        verify(client, never()).userInfo(anyString());
        verify(verifier).verifyNonce("theIdToken", "nnnccc");
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theAccessToken"));
        assertThat(tokens.getIdToken(), is("theIdToken"));
    }

    @Test
    public void shouldThrowOnFailToVerifyIdToken() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        exception.expectMessage("An error occurred while trying to verify the Id Token.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        RandomStorage.setSessionNonce(req, "nnnccc");
        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenThrow(JWTVerificationException.class);

        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifier);
        handler.process(req);

        verify(client, never()).userInfo(anyString());
        verify(verifier).verifyNonce("theIdToken", "nnnccc");
    }

    @Test
    public void shouldThrowOnFailToVerifyIdTokenWhenPublicKeyIsInvalid() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.missing_jwt_public_key_error"));
        exception.expectMessage("An error occurred while trying to verify the Id Token.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        RandomStorage.setSessionNonce(req, "nnnccc");
        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenThrow(JwkException.class);

        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifier);
        handler.process(req);

        verify(client, never()).userInfo(anyString());
    }

    @Test
    public void shouldThrowIfUserIdNotReturnedOnVerifyIdToken() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.unknown_error"));
        exception.expectMessage("An error occurred while trying to verify the user identity: The 'sub' claim contained in the token was null.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");

        when(verifier.verifyNonce("theIdToken", "nnnccc")).thenReturn(null);

        RequestProcessor handler = new RequestProcessor(client, "token id_token", verifier);
        handler.process(req);

        verify(client, never()).userInfo(anyString());
        verify(verifier).verifyNonce("theIdToken", "nnnccc");
    }

    @Test
    public void shouldVerifyAccessTokenWhenIdTokenIsMissing() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);

        RequestProcessor handler = new RequestProcessor(client, "token", verifier);
        Tokens tokens = handler.process(req);

        verifyNoMoreInteractions(verifier);
        verify(client).userInfo("theAccessToken");
        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theAccessToken"));
        assertThat(tokens.getIdToken(), is(nullValue()));
    }

    @Test
    public void shouldThrowOnFailToVerifyAccessTokenWhenIdTokenIsMissing() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.api_error"));
        exception.expectMessage("An error occurred while trying to verify the Access Token.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        when(client.userInfo("theAccessToken")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(client, "token", verifier);
        handler.process(req);

        verifyNoMoreInteractions(verifier);
        verify(client, never()).userInfo(anyString());
    }

    @Test
    public void shouldThrowIfUserIdIsNotReturnedOnFailToVerifyAccessTokenWhenIdTokenIsMissing() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.unknown_error"));
        exception.expectMessage("An error occurred while trying to verify the user identity: The 'sub' claim contained in the token was null.");

        Map<String, Object> params = new HashMap<>();
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        Request userInfoRequest = mock(Request.class);
        when(userInfo.getValues()).thenReturn(Collections.<String, Object>emptyMap());
        when(userInfoRequest.execute()).thenReturn(userInfo);
        when(client.userInfo("theAccessToken")).thenReturn(userInfoRequest);

        RequestProcessor handler = new RequestProcessor(client, "token", verifier);
        handler.process(req);

        verifyNoMoreInteractions(verifier);
        verify(client, never()).userInfo(anyString());
    }


    @Test
    public void shouldFetchUserIdUsingTheBestAccessTokenObtainedAfterCodeExchange() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
        TokenHolder holder = mock(TokenHolder.class);
        when(holder.getAccessToken()).thenReturn("theBestAccessToken");
        when(codeExchangeRequest.execute()).thenReturn(holder);
        when(client.userInfo("theBestAccessToken")).thenReturn(userInfoRequest);

        RequestProcessor handler = new RequestProcessor(client, "code", verifier);
        Tokens tokens = handler.process(req);
        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
        verify(client).userInfo("theBestAccessToken");

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theBestAccessToken"));
        assertThat(tokens.getIdToken(), is(nullValue()));
    }

    @Test
    public void shouldReturnUserIdAfterVerifyingTheBestIdTokenObtainedAfterCodeExchange() throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        RandomStorage.setSessionNonce(req, "nnnccc");
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);
        TokenHolder holder = mock(TokenHolder.class);
        when(holder.getIdToken()).thenReturn("theBestIdToken");
        when(codeExchangeRequest.execute()).thenReturn(holder);
        when(verifier.verifyNonce("theBestIdToken", "nnnccc")).thenReturn("auth0|user123");

        RequestProcessor handler = new RequestProcessor(client, "code", verifier);
        Tokens tokens = handler.process(req);
        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
        verify(client, never()).userInfo(anyString());
        verify(verifier).verifyNonce("theBestIdToken", "nnnccc");

        assertThat(tokens, is(notNullValue()));
        assertThat(tokens.getAccessToken(), is("theAccessToken"));
        assertThat(tokens.getIdToken(), is("theBestIdToken"));
    }

    @Test
    public void shouldThrowOnFailToExchangeTheAuthorizationCodeOnCodeGrant() throws Exception {
        exception.expect(IdentityVerificationException.class);
        exception.expect(IdentityVerificationExceptionMatcher.hasCode("a0.api_error"));
        exception.expectMessage("An error occurred while exchanging the Authorization Code for Auth0 Tokens.");

        Map<String, Object> params = new HashMap<>();
        params.put("code", "abc123");
        params.put("state", "1234");
        params.put("access_token", "theAccessToken");
        params.put("id_token", "theIdToken");
        HttpServletRequest req = getRequest(params);
        RandomStorage.setSessionState(req, "1234");
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenThrow(Auth0Exception.class);

        RequestProcessor handler = new RequestProcessor(client, "code", verifier);
        handler.process(req);
        verify(client).exchangeCode("abc123", "https://me.auth0.com:80/callback");
    }

    @Test
    public void shouldBuildAuthorizeUrl() throws Exception {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "code", verifier);
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
    public void shouldNotSetNonceIfRequestTypeDoesNotContainIdToken() throws Exception {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "code", verifier);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, not(containsString("nonce=nonce")));
    }

    @Test
    public void shouldSetNonceIfRequestTypeContainsIdToken() throws Exception {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "id_token", verifier);
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, containsString("nonce=nonce"));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithNonceAndFormPostIfResponseTypeContainsIdToken() throws Exception {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "id_token", verifier);
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
    public void shouldBuildAuthorizeUrlWithFormPostIfResponseTypeContainsToken() throws Exception {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor(client, "token", verifier);
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
    public void shouldGetAuthAPIClient() throws Exception {
        RequestProcessor handler = new RequestProcessor(client, "responseType", verifier);
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