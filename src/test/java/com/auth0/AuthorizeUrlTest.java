package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.PushedAuthorizationResponse;
import com.auth0.net.Request;
import com.auth0.net.Response;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.MockedStatic;

import org.mockito.Mockito;

import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class AuthorizeUrlTest {
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpSession session;
    private CustomMockHttpServletResponse response;

    private AuthAPI client;

    private static MockedStatic<RandomStorage> mockedRandomStorage;
    private static MockedStatic<SessionUtils> mockedSessionUtils;


    @BeforeEach
    public void setUp() {
        client = new AuthAPI("domain.auth0.com", "clientId", "clientSecret");
        request = mock(jakarta.servlet.http.HttpServletRequest.class);
        session = mock(HttpSession.class); // Mock the session
        when(request.getSession()).thenReturn(session); // Ensure request.getSession() returns the mocked session
        response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());
    }

    @BeforeAll
    public static void setUpStaticMocks() {
        // Mock RandomStorage static methods
        mockedRandomStorage = Mockito.mockStatic(RandomStorage.class);
        mockedRandomStorage.when(() -> RandomStorage.setSessionState(any(HttpServletRequest.class), anyString()))
                .thenAnswer(invocation -> null);
        mockedRandomStorage.when(() -> RandomStorage.setSessionNonce(any(HttpServletRequest.class), anyString()))
                .thenAnswer(invocation -> null);
        mockedRandomStorage.when(() -> RandomStorage.removeSessionNonce(any(HttpServletRequest.class)))
                .thenReturn("mockedNonce");

        // Mock SessionUtils static methods
        mockedSessionUtils = Mockito.mockStatic(SessionUtils.class);
        mockedSessionUtils.when(() -> SessionUtils.set(any(HttpServletRequest.class), anyString(), any()))
                .thenAnswer(invocation -> null);
        mockedSessionUtils.when(() -> SessionUtils.remove(any(HttpServletRequest.class), anyString()))
                .thenReturn("mockedValue");
    }

    @AfterAll
    public static void tearDownStaticMocks() {
        // Close the static mocks to deregister them
        if (mockedRandomStorage != null) {
            mockedRandomStorage.close();
        }
        if (mockedSessionUtils != null) {
            mockedSessionUtils.close();
        }
    }

    @Test // TestNG @Test annotation
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
        assertThat(headers, containsInAnyOrder("com.auth0.nonce=asdfghjkl; Max-Age=600; Secure; HttpOnly; SameSite=None"));
        assertThat(headers, containsInAnyOrder("_com.auth0.nonce=asdfghjkl; Max-Age=600; HttpOnly"));
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
        assertThat(headers, containsInAnyOrder("com.auth0.nonce=asdfghjkl; Max-Age=600; Secure; HttpOnly; SameSite=None"));
    }

    @Test
    public void shouldSetStateSameSiteAndLegacyCookieByDefault() {
        String url = new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                .withState("asdfghjkl")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));
        assertThat(headers, hasItem("com.auth0.state=asdfghjkl; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=asdfghjkl; HttpOnly; Max-Age=600"));
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
        assertThat(headers, hasItem(allOf(
                containsString("com.auth0.state=asdfghjkl"),
                containsString("Max-Age=600"),
                containsString("Secure"),
                containsString("HttpOnly"),
                containsString("SameSite=None")
        )));
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
        assertThat(headers, containsInAnyOrder("com.auth0.state=asdfghjkl; Max-Age=600; Secure; HttpOnly; SameSite=Lax"));
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
        assertThat(headers, containsInAnyOrder("com.auth0.state=asdfghjkl; Max-Age=600; Secure; HttpOnly; SameSite=None"));
        assertThat(headers, containsInAnyOrder("_com.auth0.state=asdfghjkl; Max-Age=600; HttpOnly"));
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
        // Here, passing null for HttpServletResponse means cookies won't be set via that path.
        // The `capturedCookies` list will remain empty.
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
        // Using TestNG's Assert.assertThrows
        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    public void shouldThrowWhenChangingTheRedirectURI() {
        // Using TestNG's Assert.assertThrows
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("redirect_uri", "new_value"));
    }

    @Test
    public void shouldThrowWhenChangingTheResponseType() {
        // Using TestNG's Assert.assertThrows
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("response_type", "new_value"));
    }

    @Test
    public void shouldThrowWhenChangingTheStateUsingCustomParameterSetter() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("state", "new_value"));
    }

    @Test
    public void shouldThrowWhenChangingTheNonceUsingCustomParameterSetter() {
        // Using TestNG's Assert.assertThrows
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuthorizeUrl(client, request, response, "https://redirect.to/me", "id_token token")
                        .withParameter("nonce", "new_value"));
    }

    @Test
    public void shouldGetAuthorizeUrlFromPAR() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);

        Response<PushedAuthorizationResponse> pushedAuthorizationResponseResponse = mock(Response.class);
        when(requestMock.execute()).thenReturn(pushedAuthorizationResponseResponse);
        when(requestMock.execute().getBody()).thenReturn(new PushedAuthorizationResponse("urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2", 90));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;

        HttpServletResponse mockedResponse = mock(HttpServletResponse.class);
        CustomMockHttpServletResponse customResponse = new CustomMockHttpServletResponse(mockedResponse);

        String url = new AuthorizeUrl(authAPIStub, request, customResponse, "https://domain.com/callback", "code")
                .fromPushedAuthorizationRequest();

        assertThat(url, is("https://domain.com/authorize?client_id=clientId&request_uri=urn%3Aexample%3Abwc4JK-ESC0w8acc191e-Y1LTC2"));
    }

    @Test
    public void fromPushedAuthorizationRequestThrowsWhenRequestUriIsNull() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);
        Response<PushedAuthorizationResponse> pushedAuthorizationResponseResponse = mock(Response.class);
        when(requestMock.execute()).thenReturn(pushedAuthorizationResponseResponse);
        when(requestMock.execute().getBody()).thenReturn(new PushedAuthorizationResponse(null, 90));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;

        HttpServletResponse mockedResponse = mock(HttpServletResponse.class);
        CustomMockHttpServletResponse customResponse = new CustomMockHttpServletResponse(mockedResponse);


        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            new AuthorizeUrl(authAPIStub, request, customResponse, "https://domain.com/callback", "code")
                    .fromPushedAuthorizationRequest();
        });

        assertThat(exception.getMessage(), is("The PAR request returned a missing or empty request_uri value"));
    }
    @Test
    public void fromPushedAuthorizationRequestThrowsWhenRequestUriIsEmpty() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);
        Response<PushedAuthorizationResponse> pushedAuthorizationResponseResponse = mock(Response.class);
        when(requestMock.execute()).thenReturn(pushedAuthorizationResponseResponse);
        when(pushedAuthorizationResponseResponse.getBody())
                .thenReturn(new PushedAuthorizationResponse("", 90));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            new AuthorizeUrl(authAPIStub, request, response, "https://domain.com/callback", "code")
                    .fromPushedAuthorizationRequest();
        });

        assertThat(exception.getMessage(), is("The PAR request returned a missing or empty request_uri value"));
    }

    @Test
    public void fromPushedAuthorizationRequestThrowsWhenExpiresInIsNull() throws Exception {
        AuthAPIStub authAPIStub = new AuthAPIStub("https://domain.com", "clientId", "clientSecret");
        Request requestMock = mock(Request.class);
        Response<PushedAuthorizationResponse> pushedAuthorizationResponseResponse = mock(Response.class);
        when(requestMock.execute()).thenReturn(pushedAuthorizationResponseResponse);
        when(pushedAuthorizationResponseResponse.getBody())
                .thenReturn(new PushedAuthorizationResponse("urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2", null));

        authAPIStub.pushedAuthorizationResponseRequest = requestMock;

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> {
            new AuthorizeUrl(authAPIStub, request, response, "https://domain.com/callback", "code")
                    .fromPushedAuthorizationRequest();
        });

        assertThat(exception.getMessage(), is("The PAR request returned a missing expires_in value"));
    }

    @Test
    public void fromPushedAuthorizationRequestThrowsWhenRequestThrows() throws Exception {
        AuthAPI authAPIMock = mock(AuthAPI.class);
        Request requestMock = mock(Request.class);

        when(requestMock.execute()).thenThrow(new Auth0Exception("error"));
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

        public AuthAPIStub(String domain, String clientId, String clientSecret) {
            super(domain, clientId, clientSecret);
        }

        @Override
        public Request<PushedAuthorizationResponse> pushedAuthorizationRequest(String redirectUri, String responseType, Map<String, String> params) {
            return pushedAuthorizationResponseRequest;
        }
    }
}
