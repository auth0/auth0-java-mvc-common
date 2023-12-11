package com.auth0;

import com.auth0.client.HttpOptions;
import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.PushedAuthorizationResponse;
import com.auth0.net.Request;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthorizeUrlTest {

    private AuthAPI client;
    private HttpServletResponse response;
    private HttpServletRequest request;

    @BeforeEach
    public void setUp() {
        client = new AuthAPI("domain.auth0.com", "clientId", "clientSecret");
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void shouldBuildValidStringUrl() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(url, is(notNullValue()));
        assertThat(HttpUrl.parse(url), is(notNullValue()));
    }

    @Test
    public void shouldSetDefaultScope() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("scope"), is("openid"));
    }

    @Test
    public void shouldSetResponseType() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("response_type"), is("id_token token"));
    }

    @Test
    public void shouldSetRedirectUrl() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("redirect_uri"), is("https://redirect.to/me"));
    }

    @Test
    public void shouldSetConnection() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withConnection("facebook")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("connection"), is("facebook"));
    }

    @Test
    public void shouldSetAudience() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withAudience("https://api.auth0.com/")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("audience"), is("https://api.auth0.com/"));
    }

    @Test
    public void shouldSetNonceSameSiteAndLegacyCookieByDefault() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withNonce("asdfghjkl")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));
        assertThat(headers, hasItem(matchesPattern("com.auth0.nonce=asdfghjkl; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
        assertThat(headers, hasItem(matchesPattern("_com.auth0.nonce=asdfghjkl; Max-Age=600; Expires=.*?; HttpOnly")));
    }

    @Test
    public void shouldSetNonceSameSiteAndNotLegacyCookieWhenConfigured() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withNonce("asdfghjkl")
                .withLegacySameSiteCookie(false)
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        assertThat(headers, hasItem(matchesPattern("com.auth0.nonce=asdfghjkl; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
    }

    @Test
    public void shouldSetStateSameSiteAndLegacyCookieByDefault() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withState("asdfghjkl")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));
        assertThat(headers, hasItem(matchesPattern("com.auth0.state=asdfghjkl; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
        assertThat(headers, hasItem(matchesPattern("_com.auth0.state=asdfghjkl; Max-Age=600; Expires=.*?; HttpOnly")));
    }

    @Test
    public void shouldSetStateSameSiteAndNotLegacyCookieWhenConfigured() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withState("asdfghjkl")
                .withLegacySameSiteCookie(false)
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        assertThat(headers, hasItem(matchesPattern("com.auth0.state=asdfghjkl; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
    }

    @Test
    public void shouldSetSecureCookieWhenConfiguredTrue() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "code")
                .withState("asdfghjkl")
                .withSecureCookie(true)
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        assertThat(headers, hasItem(matchesPattern("com.auth0.state=asdfghjkl; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=Lax")));
    }

    @Test
    public void shouldSetSecureCookieWhenConfiguredFalseAndSameSiteNone() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token")
                .withState("asdfghjkl")
                .withSecureCookie(false)
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));
        assertThat(headers, hasItem(matchesPattern("com.auth0.state=asdfghjkl; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
        assertThat(headers, hasItem(matchesPattern("_com.auth0.state=asdfghjkl; Max-Age=600; Expires=.*?; HttpOnly")));
    }

    @Test
    public void shouldSetNoCookiesWhenNonceAndStateNotSet() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), nullValue());
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), nullValue());

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

    @Test
    public void shouldSetNoSessionValuesWhenNonceAndStateNotSet() {
        String url = new AuthorizeUrl(client, request, null, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), nullValue());
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), nullValue());

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

    @Test
    public void shouldSetScope() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withScope("openid profile email")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("scope"), is("openid profile email"));
    }

    @Test
    public void shouldSetCustomParameterScope() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withParameter("custom", "value")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("custom"), is("value"));
    }

    @Test
    public void shouldThrowWhenReusingTheInstance() {
        AuthorizeUrl builder = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token");
        String firstCall = builder.build();
        assertThat(firstCall, is(notNullValue()));
        IllegalStateException e = assertThrows(IllegalStateException.class, builder::build);
        assertEquals("The AuthorizeUrl instance must not be reused.", e.getMessage());
    }

    @Test
    public void shouldThrowWhenChangingTheRedirectURI() {
        IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("redirect_uri", "new_value"));
        assertEquals("Redirect URI cannot be changed once set.", e.getMessage());
    }

    @Test
    public void shouldThrowWhenChangingTheResponseType() {
        IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("response_type", "new_value"));
        assertEquals("Response type cannot be changed once set.", e.getMessage());
    }

    @Test
    public void shouldThrowWhenChangingTheStateUsingCustomParameterSetter() {
        IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("state", "new_value"));
        assertEquals("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.", e.getMessage());
    }

    @Test
    public void shouldThrowWhenChangingTheNonceUsingCustomParameterSetter() {
        IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("nonce", "new_value"));
        assertEquals("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.", e.getMessage());
    }

    @Test
    public void shouldGetAuthorizeUrlFromPAR() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);

        when(requestMock.execute()).thenReturn(new PushedAuthorizationResponse("urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2", 90));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;
        String url = new AuthorizeUrl(authAPIStub, request, response, "https://domain.com/callback", "code")
                .fromPushedAuthorizationRequest();

        assertThat(url, is("https://domain.com/authorize?client_id=clientId&request_uri=urn%3Aexample%3Abwc4JK-ESC0w8acc191e-Y1LTC2"));
    }

    @Test
    public void fromPushedAuthorizationRequestThrowsWhenRequestUriIsNull() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);
        when(requestMock.execute()).thenReturn(new PushedAuthorizationResponse(null, 90));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            new AuthorizeUrl(authAPIStub, request, response, "https://domain.com/callback", "code")
                    .fromPushedAuthorizationRequest();
        });

        assertThat(exception.getMessage(), is("The PAR request returned a missing or empty request_uri value"));
    }

    @Test
    public void fromPushedAuthorizationRequestThrowsWhenRequestUriIsEmpty() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);
        when(requestMock.execute()).thenReturn(new PushedAuthorizationResponse("urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2", null));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            new AuthorizeUrl(authAPIStub, request, response, "https://domain.com/callback", "code")
                    .fromPushedAuthorizationRequest();
        });

        assertThat(exception.getMessage(), is("The PAR request returned a missing expires_in value"));
    }

    @Test
    public void fromPushedAuthorizationRequestThrowsWhenExpiresInIsNull() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);
        when(requestMock.execute()).thenReturn(new PushedAuthorizationResponse(null, 90));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            new AuthorizeUrl(authAPIStub, request, response, "https://domain.com/callback", "code")
                    .fromPushedAuthorizationRequest();
        });

        assertThat(exception.getMessage(), is("The PAR request returned a missing or empty request_uri value"));
    }

    @Test
    public void fromPushedAuthorizationRequestThrowsWhenRequestThrows() throws Exception {
        AuthAPI authAPIMock = mock(AuthAPI.class);
        Request requestMock = mock(Request.class);

        when(requestMock.execute())
                .thenThrow(new Auth0Exception("error"));
        when(authAPIMock.pushedAuthorizationRequest(eq("https://domain.com/callback"), eq("code"), anyMap()))
                .thenReturn(requestMock);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            new AuthorizeUrl(authAPIMock, request, response, "https://domain.com/callback", "code")
                    .fromPushedAuthorizationRequest();
        });

        assertThat(exception.getMessage(), is("error"));
        assertThat(exception.getCause(), instanceOf(Auth0Exception.class));
    }

    static class AuthAPIStub extends AuthAPI {

        Request<PushedAuthorizationResponse> pushedAuthorizationResponseRequest;

        public AuthAPIStub(String domain, String clientId, String clientSecret, HttpOptions options) {
            super(domain, clientId, clientSecret, options);
        }

        public AuthAPIStub(String domain, String clientId, String clientSecret) {
            super(domain, clientId, clientSecret);
        }

        @Override
        public Request<PushedAuthorizationResponse> pushedAuthorizationRequest(String redirectUri, String responseType, Map<String, String> params) {
            return pushedAuthorizationResponseRequest;
        }
    }
}
