package com.auth0;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.hamcrest.beans.HasPropertyWithValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.http.Cookie;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

public class TransientCookieStoreTest {

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    private List<String> responseHeaders;
    private List<Cookie> addedCookies;


    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        addedCookies = new ArrayList<>();

        // Capture added cookies directly
        doAnswer(invocation -> {
            Cookie cookie = invocation.getArgument(0);
            addedCookies.add(cookie);
            return null;
        }).when(response).addCookie(org.mockito.ArgumentMatchers.any(Cookie.class));
    }

    @Test
    public void shouldNotSetCookieIfStateIsNull() {
        TransientCookieStore.storeState(response, null, SameSite.NONE, true, false, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

    @Test
    public void shouldNotSetCookieIfNonceIsNull() {
        TransientCookieStore.storeNonce(response, null, SameSite.NONE, true, false, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

//    @Test
//    public void shouldHandleSpecialCharsWhenStoringState() throws Exception {
//        String stateVal = ";state = ,va\\lu;e\"";
//        TransientCookieStore.storeState(response, stateVal, SameSite.NONE, true, false, null);
//
////        Collection<String> headers = response.getHeaders("Set-Cookie");
////
////        headers.forEach(System.out::println);
////
////        assertThat(responseHeaders.size(), is(2));
//
//        assertThat(addedCookies.size(), is(2));
//
//        String expectedEncodedState = URLEncoder.encode(stateVal, "UTF-8");
//        assertThat(headers, hasItem(
//                String.format("com.auth0.state=%s; HttpOnly; Max-Age=600; SameSite=None; Secure", expectedEncodedState)));
//        assertThat(headers, hasItem(
//                String.format("_com.auth0.state=%s; HttpOnly; Max-Age=600", expectedEncodedState)));
//    }

    @Test
    public void shouldSetStateSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, false, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=123456; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, false, false, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
    }

    @Test
    public void shouldSetSecureCookieWhenSameSiteLaxAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, true, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=Lax; Secure"));
    }

    @Test
    public void shouldSetSecureFallbackCookieWhenSameSiteNoneAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, true, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=123456; HttpOnly; Max-Age=600; Secure"));
    }

    @Test
    public void shouldNotSetSecureCookieWhenSameSiteLaxAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, false, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=Lax"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", SameSite.NONE, true, false, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.nonce=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.nonce=123456; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", SameSite.NONE, false, false, null);

        Collection<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.nonce=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
    }

    @Test
    public void shouldRemoveStateSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.state", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.state", "123456");

        Cookie[] cookies = {cookie1, cookie2};
        when(request.getCookies()).thenReturn(cookies);

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("123456"));

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response, times(2)).addCookie(cookieCaptor.capture());

        List<Cookie> cookieList = cookieCaptor.getAllValues();
        assertThat(cookieList.size(), is(2));

        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveStateSameSiteCookie() {
        Cookie cookie1 = new Cookie("com.auth0.state", "123456");

        Cookie[] simulatedCookies = {cookie1};
        when(request.getCookies()).thenReturn(simulatedCookies);

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("123456"));

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response, times(1)).addCookie(cookieCaptor.capture());

        List<Cookie> cookieList = cookieCaptor.getAllValues();
        assertThat(cookieList.size(), is(1));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveStateFallbackCookie() {
        Cookie cookie1 = new Cookie("_com.auth0.state", "123456");

        Cookie[] simulatedCookies = {cookie1};
        when(request.getCookies()).thenReturn(simulatedCookies);

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("123456"));

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response, times(1)).addCookie(cookieCaptor.capture());

        List<Cookie> cookieList = cookieCaptor.getAllValues();
        assertThat(cookieList.size(), is(1));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveNonceSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.nonce", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.nonce", "123456");

        Cookie[] simulatedCookies = {cookie1, cookie2};
        when(request.getCookies()).thenReturn(simulatedCookies);

        String state = TransientCookieStore.getNonce(request, response);
        assertThat(state, is("123456"));

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response, times(2)).addCookie(cookieCaptor.capture());

        List<Cookie> cookieList = cookieCaptor.getAllValues();
        assertThat(cookieList.size(), is(2));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveNonceSameSiteCookie() {
        Cookie cookie1 = new Cookie("com.auth0.nonce", "123456");

        Cookie[] simulatedCookies = {cookie1};
        when(request.getCookies()).thenReturn(simulatedCookies);

        String state = TransientCookieStore.getNonce(request, response);
        assertThat(state, is("123456"));

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response, times(1)).addCookie(cookieCaptor.capture());

        List<Cookie> cookieList = cookieCaptor.getAllValues();
        assertThat(cookieList.size(), is(1));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldRemoveNonceFallbackCookie() {
        Cookie cookie1 = new Cookie("_com.auth0.nonce", "123456");

        Cookie[] simulatedCookies = {cookie1};
        when(request.getCookies()).thenReturn(simulatedCookies);

        String state = TransientCookieStore.getNonce(request, response);
        assertThat(state, is("123456"));

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response, times(1)).addCookie(cookieCaptor.capture());

        List<Cookie> cookieList = cookieCaptor.getAllValues();
        assertThat(cookieList.size(), is(1));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(cookieList, everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }
//
//    @Test
//    public void shouldReturnEmptyStateWhenNoCookies() {
//        String state = TransientCookieStore.getState(request, response);
//        assertThat(state, is(nullValue()));
//    }
//
//    @Test
//    public void shouldReturnEmptyNonceWhenNoCookies() {
//        String nonce = TransientCookieStore.getNonce(request, response);
//        assertThat(nonce, is(nullValue()));
//    }
//
//    @Test
//    public void shouldReturnEmptyWhenNoStateCookie() {
//        Cookie cookie1 = new Cookie("someCookie", "123456");
//        request.setCookies(cookie1);
//
//        String state = TransientCookieStore.getState(request, response);
//        assertThat(state, is(nullValue()));
//    }
//
//    @Test
//    public void shouldReturnEmptyWhenNoNonceCookie() {
//        Cookie cookie1 = new Cookie("someCookie", "123456");
//        request.setCookies(cookie1);
//
//        String nonce = TransientCookieStore.getNonce(request, response);
//        assertThat(nonce, is(nullValue()));
//        assertThat(nonce, is(nullValue()));
//    }
}
