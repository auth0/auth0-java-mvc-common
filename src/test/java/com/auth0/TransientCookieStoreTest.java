package com.auth0;

import org.hamcrest.beans.HasPropertyWithValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.Cookie;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesPattern;

public class TransientCookieStoreTest {

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void shouldNotSetCookieIfStateIsNull() {
        TransientCookieStore.storeState(response, null, SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

    @Test
    public void shouldNotSetCookieIfNonceIsNull() {
        TransientCookieStore.storeNonce(response, null, SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

    @Test
    public void shouldHandleSpecialCharsWhenStoringState() throws Exception {
        String stateVal = ";state = ,va\\lu;e\"";
        TransientCookieStore.storeState(response, stateVal, SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        String expectedEncodedState = URLEncoder.encode(stateVal, "UTF-8").replaceAll("\\+", "\\\\+");
        assertThat(headers, hasItem(matchesPattern(String.format("com\\.auth0\\.state=%s; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None", expectedEncodedState))));
        assertThat(headers, hasItem(matchesPattern(String.format("_com\\.auth0\\.state=%s; Max-Age=600; Expires=.*?; HttpOnly", expectedEncodedState))));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem(matchesPattern("com\\.auth0\\.state=123456; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
        assertThat(headers, hasItem(matchesPattern("_com\\.auth0\\.state=123456; Max-Age=600; Expires=.*?; HttpOnly")));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem(matchesPattern("com\\.auth0\\.state=123456; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
    }

    @Test
    public void shouldSetSecureCookieWhenSameSiteLaxAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, true, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem(matchesPattern("com\\.auth0\\.state=123456; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=Lax")));
    }

    @Test
    public void shouldSetSecureFallbackCookieWhenSameSiteNoneAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, true, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem(matchesPattern("com\\.auth0\\.state=123456; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
        assertThat(headers, hasItem(matchesPattern("_com\\.auth0\\.state=123456; Max-Age=600; Expires=.*?; Secure; HttpOnly")));
    }

    @Test
    public void shouldNotSetSecureCookieWhenSameSiteLaxAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem(matchesPattern("com\\.auth0\\.state=123456; Max-Age=600; Expires=.*?; HttpOnly; SameSite=Lax")));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem(matchesPattern("com\\.auth0\\.nonce=123456; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
        assertThat(headers, hasItem(matchesPattern("_com\\.auth0\\.nonce=123456; Max-Age=600; Expires=.*?; HttpOnly")));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", SameSite.NONE, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem(matchesPattern("com\\.auth0\\.nonce=123456; Max-Age=600; Expires=.*?; Secure; HttpOnly; SameSite=None")));
    }

    @Test
    public void shouldRemoveStateSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.state", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.state", "123456");

        request.setCookies(cookie1, cookie2);

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(2));

        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveStateSameSiteCookie() {
        Cookie cookie1 = new Cookie("com.auth0.state", "123456");

        request.setCookies(cookie1);

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(1));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveStateFallbackCookie() {
        Cookie cookie1 = new Cookie("_com.auth0.state", "123456");

        request.setCookies(cookie1);

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(1));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveNonceSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.nonce", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.nonce", "123456");

        request.setCookies(cookie1, cookie2);

        String state = TransientCookieStore.getNonce(request, response);
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(2));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveNonceSameSiteCookie() {
        Cookie cookie1 = new Cookie("com.auth0.nonce", "123456");

        request.setCookies(cookie1);

        String state = TransientCookieStore.getNonce(request, response);
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(1));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveNonceFallbackCookie() {
        Cookie cookie1 = new Cookie("_com.auth0.nonce", "123456");

        request.setCookies(cookie1);

        String state = TransientCookieStore.getNonce(request, response);
        assertThat(state, is("123456"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(1));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldReturnEmptyStateWhenNoCookies() {
        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is(nullValue()));
    }

    @Test
    public void shouldReturnEmptyNonceWhenNoCookies() {
        String nonce = TransientCookieStore.getNonce(request, response);
        assertThat(nonce, is(nullValue()));
    }

    @Test
    public void shouldReturnEmptyWhenNoStateCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is(nullValue()));
    }

    @Test
    public void shouldReturnEmptyWhenNoNonceCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);

        String nonce = TransientCookieStore.getNonce(request, response);
        assertThat(nonce, is(nullValue()));
        assertThat(nonce, is(nullValue()));
    }
}
