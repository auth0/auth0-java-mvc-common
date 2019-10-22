package com.auth0;

import com.auth0.client.auth.AuthAPI;
import okhttp3.HttpUrl;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

public class AuthorizeUrlTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private AuthAPI client;

    @Before
    public void setUp() {
        client = new AuthAPI("domain.auth0.com", "clientId", "clientSecret");
    }

    @Test
    public void shouldBuildValidStringUrl() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(url, is(notNullValue()));
        assertThat(HttpUrl.parse(url), is(notNullValue()));
    }

    @Test
    public void shouldSetDefaultScope() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("scope"), is("openid"));
    }

    @Test
    public void shouldSetResponseType() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("response_type"), is("id_token token"));
    }

    @Test
    public void shouldSetRedirectUrl() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("redirect_uri"), is("https://redirect.to/me"));
    }

    @Test
    public void shouldSetConnection() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withConnection("facebook")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("connection"), is("facebook"));
    }

    @Test
    public void shouldSetAudience() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withAudience("https://api.auth0.com/")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("audience"), is("https://api.auth0.com/"));
    }

    @Test
    public void shouldSetNonceAndSaveTheValueOnTheRequestSession() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withNonce("asdfghjkl")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("nonce"), is("asdfghjkl"));
        String savedNonce = (String) req.getSession(true).getAttribute("com.auth0.nonce");
        assertThat(savedNonce, is("asdfghjkl"));
    }

    @Test
    public void shouldSetStateAndSaveTheValueOnTheRequestSession() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withState("asdfghjkl")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("state"), is("asdfghjkl"));
        String savedState = (String) req.getSession(true).getAttribute("com.auth0.state");
        assertThat(savedState, is("asdfghjkl"));
    }

    @Test
    public void shouldSetScope() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withScope("openid profile email")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("scope"), is("openid profile email"));
    }

    @Test
    public void shouldSetCustomParameterScope() {
        HttpServletRequest req = new MockHttpServletRequest();
        String url = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withParameter("custom", "value")
                .build();
        assertThat(HttpUrl.parse(url).queryParameter("custom"), is("value"));
    }

    @Test
    public void shouldThrowWhenReusingTheInstance() {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("The AuthorizeUrl instance must not be reused.");
        HttpServletRequest req = new MockHttpServletRequest();
        AuthorizeUrl builder = new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token");
        String firstCall = builder.build();
        assertThat(firstCall, is(notNullValue()));
        builder.build();
    }

    @Test
    public void shouldThrowWhenChangingTheRedirectURI() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Redirect URI cannot be changed once set.");
        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withParameter("redirect_uri", "new_value");
    }

    @Test
    public void shouldThrowWhenChangingTheResponseType() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Response type cannot be changed once set.");
        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withParameter("response_type", "new_value");
    }

    @Test
    public void shouldThrowWhenChangingTheStateUsingCustomParameterSetter() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.");
        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withParameter("state", "new_value");
    }

    @Test
    public void shouldThrowWhenChangingTheNonceUsingCustomParameterSetter() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Please, use the dedicated methods for setting the 'nonce' and 'state' parameters.");
        HttpServletRequest req = new MockHttpServletRequest();
        new AuthorizeUrl(client, req, "https://redirect.to/me", "id_token token")
                .withParameter("nonce", "new_value");
    }
}