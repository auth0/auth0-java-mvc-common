package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.Response;
import com.auth0.net.TokenRequest;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.io.StringWriter;

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

    // These will now be Mockito mocks directly
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private HttpSession session; // Mock the session as well

    @BeforeEach
    public void setUp() {
        // Use openMocks instead of initMocks for newer Mockito versions
        MockitoAnnotations.openMocks(this);

        // Configure the mocked HttpServletRequest to return our mocked session
        when(request.getSession(anyBoolean())).thenReturn(session);
        when(request.getSession()).thenReturn(session);

        // Common setup for HttpServletRequest URL parts, as many tests rely on the callback URL
        when(request.getScheme()).thenReturn("https");
        when(request.getServerName()).thenReturn("me.auth0.com");
        when(request.getServerPort()).thenReturn(80);
        when(request.getRequestURI()).thenReturn("/callback");
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://me.auth0.com:80/callback"));

        // Common setup for HttpServletResponse writer if tests need to capture output
        try {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            when(response.getWriter()).thenReturn(printWriter);
        } catch (Exception e) {
            // In a real scenario, you might want to handle this more robustly
            // For tests, it's often fine to rethrow as a RuntimeException or ignore if writer isn't used.
            throw new RuntimeException("Failed to mock response writer", e);
        }
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
        // As per the original test, this still throws NullPointerException if verifyOptions is null.
        assertThrows(NullPointerException.class, () -> new RequestProcessor.Builder(client, "responseType", null));
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasError() throws Exception {
        // Configure the mocked request for this specific test
        when(request.getParameter("error")).thenReturn("something happened");
        // Ensure other parameters are null if not set
        when(request.getParameter("state")).thenReturn(null);
        when(request.getCookies()).thenReturn(null); // No cookies for this scenario

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("something happened"));
        assertEquals("The request contains an error", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasInvalidState() throws Exception {
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "9999")});
        when(session.getAttribute("com.auth0.state")).thenReturn(null); // Ensure session state is not interfering

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasInvalidStateInSession() throws Exception {
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(null); // No cookies for this scenario
        when(session.getAttribute("com.auth0.state")).thenReturn("9999");

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasMissingStateParameter() throws Exception {
        when(request.getParameter("state")).thenReturn(null); // Missing state parameter
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});
        when(session.getAttribute("com.auth0.state")).thenReturn(null);

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one. No state parameter was found on the authorization response.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfRequestHasMissingStateCookie() throws Exception {
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(null); // Missing state cookie
        when(session.getAttribute("com.auth0.state")).thenReturn(null); // Missing state session attribute

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.invalid_state"));
        assertEquals("The received state doesn't match the expected one. No state cookie or state session attribute found. Check that you are using non-deprecated methods and that cookies are not being removed on the server.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestIsMissingIdToken() throws Exception {
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});
        when(request.getParameter("id_token")).thenReturn(null); // Missing ID token

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.missing_id_token"));
        assertEquals("ID Token is missing from the response.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfTokenRequestIsMissingAccessToken() throws Exception {
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});
        when(request.getParameter("access_token")).thenReturn(null); // Missing access token

        RequestProcessor handler = new RequestProcessor.Builder(client, "token", verifyOptions)
                .build();
        InvalidRequestException e = assertThrows(InvalidRequestException.class, () -> handler.process(request, response));
        assertThat(e, InvalidRequestExceptionMatcher.hasCode("a0.missing_access_token"));
        assertEquals("Access Token is missing from the response.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenRequestDoesNotPassIdTokenVerification() throws Exception {
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});
        when(request.getParameter("id_token")).thenReturn("frontIdToken");

        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e, IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        assertEquals("An error occurred while trying to verify the ID Token.", e.getMessage());
    }

    @Test
    public void shouldReturnTokensOnProcessIfIdTokenRequestPassesIdTokenVerification() throws Exception {
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234"), new Cookie("com.auth0.nonce", "5678")});
        when(request.getParameter("id_token")).thenReturn("frontIdToken");

        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        Tokens process = handler.process(request, response);
        assertThat(process, is(notNullValue()));
        assertThat(process.getIdToken(), is("frontIdToken"));
    }

    @Test
    public void shouldThrowOnProcessIfIdTokenCodeRequestDoesNotPassIdTokenVerification() throws Exception {
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getParameter("id_token")).thenReturn("frontIdToken");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});

        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e, IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        assertEquals("An error occurred while trying to verify the ID Token.", e.getMessage());
    }

    @Test
    public void shouldThrowOnProcessIfCodeRequestFailsToExecuteCodeExchange() throws Exception {
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        when(codeExchangeRequest.execute()).thenThrow(new Auth0Exception("API Error")); // Use a concrete Auth0Exception
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
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        Response<TokenHolder> tokenResponse = mock(Response.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder); // Corrected this line
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        doThrow(TokenValidationException.class).when(tokenVerifier).verify(eq("backIdToken"), eq(verifyOptions));

        RequestProcessor handler = new RequestProcessor.Builder(client, "code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        IdentityVerificationException e = assertThrows(IdentityVerificationException.class, () -> handler.process(request, response));
        assertThat(e, IdentityVerificationExceptionMatcher.hasCode("a0.invalid_jwt_error"));
        assertEquals("An error occurred while trying to verify the ID Token.", e.getMessage());
    }

    @Test
    public void shouldReturnTokensOnProcessIfIdTokenCodeRequestPassesIdTokenVerification() throws Exception {
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getParameter("id_token")).thenReturn("frontIdToken");
        when(request.getParameter("expires_in")).thenReturn("8400");
        when(request.getParameter("token_type")).thenReturn("frontTokenType");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        Response<TokenHolder> tokenResponse = mock(Response.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder); // Corrected this line
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

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
    public void shouldReturnTokensOnProcessIfIdTokenCodeRequestPassesIdTokenVerificationWhenUsingSessionStorage() throws Exception {
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getParameter("id_token")).thenReturn("frontIdToken");
        when(request.getParameter("expires_in")).thenReturn("8400");
        when(request.getParameter("token_type")).thenReturn("frontTokenType");
        when(request.getCookies()).thenReturn(null); // No cookies for this scenario
        when(session.getAttribute("com.auth0.state")).thenReturn("1234");

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        Response<TokenHolder> tokenResponse = mock(Response.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder); // Corrected this line
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

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
    public void shouldReturnTokensOnProcessIfIdTokenCodeRequestPassesIdTokenVerificationWhenUsingSessionStorageWithNullSession() throws Exception {
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getParameter("id_token")).thenReturn("frontIdToken");
        when(request.getParameter("expires_in")).thenReturn("8400");
        when(request.getParameter("token_type")).thenReturn("frontTokenType");
        when(request.getCookies()).thenReturn(null); // No cookies for this scenario
        when(session.getAttribute("com.auth0.state")).thenReturn("1234");

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        Response<TokenHolder> tokenResponse = mock(Response.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder); // Corrected this line
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token code", verifyOptions)
                .withIdTokenVerifier(tokenVerifier)
                .build();
        Tokens tokens = handler.process(request, null); // Passing null for HttpServletResponse here

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
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getParameter("id_token")).thenReturn("frontIdToken");
        when(request.getParameter("access_token")).thenReturn("frontAccessToken");
        when(request.getParameter("expires_in")).thenReturn("8400");
        when(request.getParameter("token_type")).thenReturn("frontTokenType");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        Response<TokenHolder> tokenResponse = mock(Response.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getAccessToken()).thenReturn("backAccessToken");
        when(tokenHolder.getRefreshToken()).thenReturn("backRefreshToken");
        when(tokenHolder.getExpiresIn()).thenReturn(4800L);
        when(tokenHolder.getTokenType()).thenReturn("backTokenType");
        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder); // Corrected this line
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        doNothing().when(tokenVerifier).verify(eq("frontIdToken"), eq(verifyOptions));

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
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        Response<TokenHolder> tokenResponse = mock(Response.class);
        when(tokenHolder.getIdToken()).thenReturn("backIdToken");
        when(tokenHolder.getAccessToken()).thenReturn("backAccessToken");
        when(tokenHolder.getRefreshToken()).thenReturn("backRefreshToken");
        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder); // Corrected this line
        when(client.exchangeCode("abc123", "https://me.auth0.com:80/callback")).thenReturn(codeExchangeRequest);

        doNothing().when(tokenVerifier).verify(eq("backIdToken"), eq(verifyOptions));

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
        when(request.getParameter("code")).thenReturn("abc123");
        when(request.getParameter("state")).thenReturn("1234");
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("com.auth0.state", "1234")});

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        TokenHolder tokenHolder = mock(TokenHolder.class); // By default, all fields are null
        Response<TokenHolder> tokenResponse = mock(Response.class);
        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder); // Corrected this line
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
        // Request and response mocks are already set up in @BeforeEach
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https%3A%2F%2Fredirect.uri%2Fhere")); // URL encoded
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
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", null); // Null nonce
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, not(containsString("nonce="))); // Should not contain "nonce=" at all
    }

    @Test
    public void shouldBuildAuthorizeUrlWithNonceAndFormPostIfResponseTypeIsIdToken() {
        AuthAPI client = new AuthAPI("me.auth0.com", "clientId", "clientSecret");
        RequestProcessor handler = new RequestProcessor.Builder(client, "id_token", verifyOptions)
                .build();
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response,"https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https%3A%2F%2Fredirect.uri%2Fhere"));
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
        AuthorizeUrl builder = handler.buildAuthorizeUrl(request, response, "https://redirect.uri/here", "state", "nonce");
        String authorizeUrl = builder.build();

        assertThat(authorizeUrl, is(notNullValue()));
        assertThat(authorizeUrl, CoreMatchers.startsWith("https://me.auth0.com/authorize?"));
        assertThat(authorizeUrl, containsString("client_id=clientId"));
        assertThat(authorizeUrl, containsString("redirect_uri=https%3A%2F%2Fredirect.uri%2Fhere"));
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

    // --- Dummy Classes (Replace with your actual implementations) ---
    // These are minimal implementations to allow the test file to compile.
    // Ensure your actual project has these classes defined correctly.

    // Dummy RequestProcessor.Builder and RequestProcessor classes
//    static class RequestProcessor {
//        private final AuthAPI client;
//        private final String responseType;
//        private final IdTokenVerifier.Options verifyOptions;
//        private IdTokenVerifier tokenVerifier;
//        public boolean useLegacySameSiteCookie = true; // Added for the test case
//
//        private RequestProcessor(Builder builder) {
//            this.client = builder.client;
//            this.responseType = builder.responseType;
//            this.verifyOptions = builder.verifyOptions;
//            this.tokenVerifier = builder.tokenVerifier;
//        }
//
//        public static boolean requiresFormPostResponseMode(String responseType) {
//            return "id_token".equalsIgnoreCase(responseType) || "token".equalsIgnoreCase(responseType) || "id_token code".equalsIgnoreCase(responseType) || "id_token token code".equalsIgnoreCase(responseType);
//        }
//
//        public Tokens process(HttpServletRequest request, HttpServletResponse response) throws Auth0Exception {
//            // This is a simplified implementation just to make the tests compile.
//            // You would need to put the actual logic from your RequestProcessor here.
//
//            // Simulate error handling
//            if (request.getParameter("error") != null) {
//                throw new InvalidRequestException("The request contains an error", request.getParameter("error"));
//            }
//
//            // Simulate state verification
//            String requestState = request.getParameter("state");
//            String cookieState = null;
//            if (request.getCookies() != null) {
//                for (Cookie cookie : request.getCookies()) {
//                    if ("com.auth0.state".equals(cookie.getName())) {
//                        cookieState = cookie.getValue();
//                        break;
//                    }
//                }
//            }
//            // Use getSession(false) to avoid creating a new session if one doesn't exist,
//            // which is typical for state checks.
//            HttpSession currentSession = request.getSession(false);
//            String sessionState = (currentSession != null) ? (String) currentSession.getAttribute("com.auth0.state") : null;
//
//            if (requestState != null && (cookieState == null && sessionState == null)) {
//                throw new InvalidRequestException("The received state doesn't match the expected one. No state cookie or state session attribute found. Check that you are using non-deprecated methods and that cookies are not being removed on the server.", "a0.invalid_state");
//            }
//
//            if (requestState == null && (cookieState != null || sessionState != null)) {
//                throw new InvalidRequestException("The received state doesn't match the expected one. No state parameter was found on the authorization response.", "a0.invalid_state");
//            }
//
//            if (requestState != null && cookieState != null && !requestState.equals(cookieState)) {
//                throw new InvalidRequestException("The received state doesn't match the expected one.", "a0.invalid_state");
//            }
//
//            if (requestState != null && sessionState != null && !requestState.equals(sessionState)) {
//                throw new InvalidRequestException("The received state doesn't match the expected one.", "a0.invalid_state");
//            }
//
//            // Simulate token requests based on responseType
//            Tokens tokens = new Tokens();
//            if (responseType.contains("id_token")) {
//                String idToken = request.getParameter("id_token");
//                if (idToken == null) {
//                    throw new InvalidRequestException("ID Token is missing from the response.", "a0.missing_id_token");
//                }
//                try {
//                    if (tokenVerifier != null) {
//                        tokenVerifier.verify(idToken, verifyOptions);
//                    }
//                } catch (TokenValidationException e) {
//                    throw new IdentityVerificationException("An error occurred while trying to verify the ID Token.", "a0.invalid_jwt_error", e);
//                }
//                tokens.setIdToken(idToken);
//                if (request.getParameter("expires_in") != null) {
//                    tokens.setExpiresIn(Long.parseLong(request.getParameter("expires_in")));
//                }
//                tokens.setType(request.getParameter("token_type"));
//            }
//
//            if (responseType.contains("token")) {
//                String accessToken = request.getParameter("access_token");
//                // If access token is provided via front channel, use it. Otherwise, expect it from back channel.
//                if (accessToken != null) {
//                    tokens.setAccessToken(accessToken);
//                }
//            }
//
//            if (responseType.contains("code")) {
//                String code = request.getParameter("code");
//                if (code != null) {
//                    try {
//                        TokenRequest tokenRequest = client.exchangeCode(code, request.getRequestURL().toString());
//                        Response<TokenHolder> tokenResponse = tokenRequest.execute();
//                        TokenHolder tokenHolder = tokenResponse.getBody();
//                        if (tokenHolder != null) {
//                            // Prioritize front-channel ID token if available, otherwise use back-channel
//                            if (tokens.getIdToken() == null) {
//                                tokens.setIdToken(tokenHolder.getIdToken());
//                            }
//                            // Prioritize front-channel access token if available, otherwise use back-channel
//                            if (tokens.getAccessToken() == null) {
//                                tokens.setAccessToken(tokenHolder.getAccessToken());
//                            }
//                            tokens.setRefreshToken(tokenHolder.getRefreshToken());
//                            // Prioritize front-channel expires_in if available, otherwise use back-channel
//                            if (tokens.getExpiresIn() == null) {
//                                tokens.setExpiresIn(tokenHolder.getExpiresIn());
//                            }
//                            // Prioritize front-channel token_type if available, otherwise use back-channel
//                            if (tokens.getType() == null) {
//                                tokens.setType(tokenHolder.getTokenType());
//                            }
//
//                            // Verify ID Token from back-channel if front-channel ID Token wasn't present
//                            if (tokens.getIdToken() != null && !responseType.contains("id_token")) {
//                                try {
//                                    if (tokenVerifier != null) {
//                                        tokenVerifier.verify(tokens.getIdToken(), verifyOptions);
//                                    }
//                                } catch (TokenValidationException e) {
//                                    throw new IdentityVerificationException("An error occurred while trying to verify the ID Token.", "a0.invalid_jwt_error", e);
//                                }
//                            }
//                        }
//                    } catch (Auth0Exception e) {
//                        throw new IdentityVerificationException("An error occurred while exchanging the authorization code.", "a0.api_error", e);
//                    }
//                }
//            }
//            return tokens;
//        }
//
//        public AuthorizeUrl buildAuthorizeUrl(HttpServletRequest request, HttpServletResponse response, String redirectUri, String state, String nonce) {
//            // This is a simplified implementation for testing purposes.
//            // You'd have your actual logic here.
//            AuthorizeUrl urlBuilder = new AuthorizeUrl(client.getDomain() + "/authorize")
//                    .withClientId(client.getClientId())
//                    .withRedirectUri(redirectUri)
//                    .withResponseType(responseType)
//                    .withScope("openid")
//                    .withState(state);
//
//            if (verifyOptions != null && verifyOptions.getMaxAge() != null) {
//                urlBuilder.withParameter("max_age", String.valueOf(verifyOptions.getMaxAge()));
//            }
//
//            if (responseType.contains("id_token")) {
//                if (nonce != null) {
//                    urlBuilder.withParameter("nonce", nonce);
//                }
//                urlBuilder.withParameter("response_mode", "form_post");
//            } else if (responseType.contains("token")) {
//                urlBuilder.withParameter("response_mode", "form_post");
//            }
//
//            return urlBuilder;
//        }
//
//        public AuthAPI getClient() {
//            return client;
//        }
//
//        static class Builder {
//            private final AuthAPI client;
//            private final String responseType;
//            private final IdTokenVerifier.Options verifyOptions;
//            private IdTokenVerifier tokenVerifier;
//
//            public Builder(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions) {
//                if (client == null) throw new NullPointerException("AuthAPI client cannot be null");
//                if (responseType == null) throw new NullPointerException("responseType cannot be null");
//                if (verifyOptions == null) throw new NullPointerException("verifyOptions cannot be null");
//                this.client = client;
//                this.responseType = responseType;
//                this.verifyOptions = verifyOptions;
//            }
//
//            public Builder withIdTokenVerifier(IdTokenVerifier tokenVerifier) {
//                this.tokenVerifier = tokenVerifier;
//                return this;
//            }
//
//            public RequestProcessor build() {
//                if (this.tokenVerifier == null) {
//                    this.tokenVerifier = new IdTokenVerifier(verifyOptions); // Default verifier if not set
//                }
//                return new RequestProcessor(this);
//            }
//        }
//    }
//
//    // Dummy AuthorizeUrl class
//    static class AuthorizeUrl {
//        private final String baseUrl;
//        private final Map<String, String> parameters = new HashMap<>();
//
//        public AuthorizeUrl(String baseUrl) {
//            this.baseUrl = baseUrl;
//        }
//
//        public AuthorizeUrl withClientId(String clientId) {
//            parameters.put("client_id", clientId);
//            return this;
//        }
//
//        public AuthorizeUrl withRedirectUri(String redirectUri) {
//            parameters.put("redirect_uri", redirectUri);
//            return this;
//        }
//
//        public AuthorizeUrl withResponseType(String responseType) {
//            parameters.put("response_type", responseType);
//            return this;
//        }
//
//        public AuthorizeUrl withScope(String scope) {
//            parameters.put("scope", scope);
//            return this;
//        }
//
//        public AuthorizeUrl withState(String state) {
//            parameters.put("state", state);
//            return this;
//        }
//
//        public AuthorizeUrl withParameter(String name, String value) {
//            parameters.put(name, value);
//            return this;
//        }
//
//        public String build() {
//            StringBuilder url = new StringBuilder(baseUrl);
//            url.append("?");
//            try {
//                for (Map.Entry<String, String> entry : parameters.entrySet()) {
//                    url.append(URLEncoder.encode(entry.getKey(), "UTF-8"))
//                            .append("=")
//                            .append(URLEncoder.encode(entry.getValue(), "UTF-8"))
//                            .append("&");
//                }
//            } catch (UnsupportedEncodingException e) {
//                throw new RuntimeException(e);
//            }
//            // Remove trailing &
//            if (url.charAt(url.length() - 1) == '&') {
//                url.deleteCharAt(url.length() - 1);
//            }
//            return url.toString();
//        }
//    }
//
//    // Dummy IdTokenVerifier and IdTokenVerifier.Options classes
//    static class IdTokenVerifier {
//        private final Options options;
//
//        public IdTokenVerifier(Options options) {
//            this.options = options;
//        }
//
//        public void verify(String idToken, Options options) throws TokenValidationException {
//            // Dummy verification logic
//            if ("invalid".equals(idToken)) {
//                throw new TokenValidationException("Invalid ID Token");
//            }
//        }
//
//        static class Options {
//            private final String issuer;
//            private final String audience;
//            private final SignatureVerifier signatureVerifier;
//            private Long maxAge;
//
//            public Options(String issuer, String audience, SignatureVerifier signatureVerifier) {
//                this.issuer = issuer;
//                this.audience = audience;
//                this.signatureVerifier = signatureVerifier;
//            }
//
//            public Long getMaxAge() {
//                return maxAge;
//            }
//
//            public Options withMaxAge(Long maxAge) {
//                this.maxAge = maxAge;
//                return this;
//            }
//        }
//    }
//
//    // Dummy SignatureVerifier class
//    interface SignatureVerifier {}
//
//    // Dummy Tokens class
//    static class Tokens {
//        private String idToken;
//        private String accessToken;
//        private String refreshToken;
//        private Long expiresIn;
//        private String type;
//
//        public String getIdToken() { return idToken; }
//        public void setIdToken(String idToken) { this.idToken = idToken; }
//        public String getAccessToken() { return accessToken; }
//        public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
//        public String getRefreshToken() { return refreshToken; }
//        public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
//        public Long getExpiresIn() { return expiresIn; }
//        public void setExpiresIn(Long expiresIn) { this.expiresIn = expiresIn; }
//        public String getType() { return type; }
//        public void setType(String type) { this.type = type; }
//    }
//
//    // Dummy Exception Matcher Classes
//    static class InvalidRequestExceptionMatcher extends org.hamcrest.TypeSafeMatcher<InvalidRequestException> {
//        private final String expectedCode;
//
//        public InvalidRequestExceptionMatcher(String expectedCode) {
//            this.expectedCode = expectedCode;
//        }
//
//        public static InvalidRequestExceptionMatcher hasCode(String code) {
//            return new InvalidRequestExceptionMatcher(code);
//        }
//
//        @Override
//        protected boolean matchesSafely(InvalidRequestException item) {
//            return item.getCode().equals(expectedCode);
//        }
//
//        @Override
//        public void describeTo(org.hamcrest.Description description) {
//            description.appendText("an InvalidRequestException with code ").appendValue(expectedCode);
//        }
//    }
//
//    static class IdentityVerificationExceptionMatcher extends org.hamcrest.TypeSafeMatcher<IdentityVerificationException> {
//        private final String expectedCode;
//
//        public IdentityVerificationExceptionMatcher(String expectedCode) {
//            this.expectedCode = expectedCode;
//        }
//
//        public static IdentityVerificationExceptionMatcher hasCode(String code) {
//            return new IdentityVerificationExceptionMatcher(code);
//        }
//
//        @Override
//        protected boolean matchesSafely(IdentityVerificationException item) {
//            return item.getCode().equals(expectedCode);
//        }
//
//        @Override
//        public void describeTo(org.hamcrest.Description description) {
//            description.appendText("an IdentityVerificationException with code ").appendValue(expectedCode);
//        }
//    }
//
//    // Dummy Exception Classes
//    static class InvalidRequestException extends RuntimeException {
//        private final String code;
//        public InvalidRequestException(String message, String code) { super(message); this.code = code; }
//        public String getCode() { return code; }
//    }
//
//    static class IdentityVerificationException extends RuntimeException {
//        private final String code;
//        public IdentityVerificationException(String message, String code, Throwable cause) { super(message, cause); this.code = code; }
//        public String getCode() { return code; }
//    }
//
//    static class TokenValidationException extends RuntimeException {
//        public TokenValidationException(String message) { super(message); }
//    }
}