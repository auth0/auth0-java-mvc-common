package com.auth0;

import org.hamcrest.beans.HasPropertyWithValue;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.Cookie;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class TransientCookieStoreTest {

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void shouldSetStateSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", TransientCookieStore.SameSite.NONE, true);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=123456; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", TransientCookieStore.SameSite.NONE, false);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", TransientCookieStore.SameSite.NONE, true);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.nonce=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.nonce=123456; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", TransientCookieStore.SameSite.NONE, false);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.nonce=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
    }

    @Test
    public void shouldRemoveStateSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.state", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.state", "123456");

        request.setCookies(cookie1, cookie2);

        String state = TransientCookieStore.getState(request, response, true);
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

        String state = TransientCookieStore.getState(request, response, false);
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

        String state = TransientCookieStore.getState(request, response, true);
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

        String state = TransientCookieStore.getNonce(request, response, true);
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

        String state = TransientCookieStore.getNonce(request, response, true);
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

        String state = TransientCookieStore.getNonce(request, response, true);
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
        String state = TransientCookieStore.getState(request, response, true);
        assertThat(state, is(nullValue()));
    }

    @Test
    public void shouldReturnEmptyNonceWhenNoCookies() {
        String nonce = TransientCookieStore.getNonce(request, response, true);
        assertThat(nonce, is(nullValue()));
    }

    @Test
    public void shouldReturnEmptyWhenNoStateCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);

        String state = TransientCookieStore.getState(request, response, true);
        assertThat(state, is(nullValue()));
    }

    @Test
    public void shouldReturnEmptyWhenNoNonceCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);

        String nonce = TransientCookieStore.getNonce(request, response, true);
        assertThat(nonce, is(nullValue()));
        assertThat(nonce, is(nullValue()));
    }

//    @Test
//    public void shouldStoreInSessionIfResponseIsNull() {
//        TransientCookieStore.storeState(request, response, "123456", null, false);
//    }
}