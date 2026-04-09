package com.auth0;

import org.hamcrest.beans.HasPropertyWithValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.Cookie;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

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

        String expectedEncodedState = URLEncoder.encode(stateVal, "UTF-8");
        assertThat(headers, hasItem(
                String.format("com.auth0.state=%s; HttpOnly; Max-Age=600; SameSite=None; Secure", expectedEncodedState)));
        assertThat(headers, hasItem(
                String.format("_com.auth0.state=%s; HttpOnly; Max-Age=600", expectedEncodedState)));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=123456; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
    }

    @Test
    public void shouldSetSecureCookieWhenSameSiteLaxAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, true, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=Lax; Secure"));
    }

    @Test
    public void shouldSetSecureFallbackCookieWhenSameSiteNoneAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, true, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=123456; HttpOnly; Max-Age=600; Secure"));
    }

    @Test
    public void shouldNotSetSecureCookieWhenSameSiteLaxAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.state=123456; HttpOnly; Max-Age=600; SameSite=Lax"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers, hasItem("com.auth0.nonce=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.nonce=123456; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeNonce(response, "123456", SameSite.NONE, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers, hasItem("com.auth0.nonce=123456; HttpOnly; Max-Age=600; SameSite=None; Secure"));
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

    private static final String TEST_SECRET = "testClientSecret123";
    private static final String TEST_DOMAIN = "tenant-a.auth0.com";

    @Test
    public void shouldStoreSignedOriginDomainCookie() {
        TransientCookieStore.storeSignedOriginDomain(response, TEST_DOMAIN,
                SameSite.LAX, null, false, TEST_SECRET);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        String header = headers.get(0);
        assertThat(header, containsString("com.auth0.origin_domain="));
        assertThat(header, containsString("SameSite=Lax"));
        assertThat(header, containsString("HttpOnly"));
    }

    @Test
    public void shouldStoreSignedOriginDomainWithSameSiteNone() {
        TransientCookieStore.storeSignedOriginDomain(response, TEST_DOMAIN,
                SameSite.NONE, null, false, TEST_SECRET);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2)); // primary + legacy fallback
        assertThat(headers.get(0), containsString("SameSite=None"));
        assertThat(headers.get(0), containsString("Secure"));
    }

    @Test
    public void shouldRetrieveAndVerifySignedOriginDomain() {
        String signedValue = SignedCookieUtils.sign(TEST_DOMAIN, TEST_SECRET);
        Cookie cookie = new Cookie("com.auth0.origin_domain", signedValue);
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_SECRET);

        assertThat(domain, is(TEST_DOMAIN));
    }

    @Test
    public void shouldReturnNullForTamperedOriginDomain() {
        Cookie cookie = new Cookie("com.auth0.origin_domain",
                "evil.auth0.com|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_SECRET);

        assertThat(domain, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForMissingOriginDomainCookie() {
        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_SECRET);

        assertThat(domain, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForWrongSecret() {
        String signedValue = SignedCookieUtils.sign(TEST_DOMAIN, TEST_SECRET);
        Cookie cookie = new Cookie("com.auth0.origin_domain", signedValue);
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, "wrong-secret");

        assertThat(domain, is(nullValue()));
    }

    @Test
    public void shouldDeleteOriginDomainCookieAfterReading() {
        String signedValue = SignedCookieUtils.sign(TEST_DOMAIN, TEST_SECRET);
        Cookie cookie = new Cookie("com.auth0.origin_domain", signedValue);
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_SECRET);
        assertThat(domain, is(TEST_DOMAIN));

        Cookie[] responseCookies = response.getCookies();
        assertThat(responseCookies, is(notNullValue()));
        boolean foundDeleted = false;
        for (Cookie c : responseCookies) {
            if ("com.auth0.origin_domain".equals(c.getName())) {
                assertThat(c.getMaxAge(), is(0));
                assertThat(c.getValue(), is(""));
                foundDeleted = true;
            }
        }
        assertThat(foundDeleted, is(true));
    }

    @Test
    public void shouldStoreAndRetrieveSignedOriginDomainEndToEnd() {
        TransientCookieStore.storeSignedOriginDomain(response, TEST_DOMAIN,
                SameSite.LAX, null, false, TEST_SECRET);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        String header = headers.get(0);
        String cookieValue = header.split(";")[0].split("=", 2)[1];

        Cookie cookie = new Cookie("com.auth0.origin_domain", cookieValue);

        MockHttpServletRequest callbackRequest = new MockHttpServletRequest();
        MockHttpServletResponse callbackResponse = new MockHttpServletResponse();
        callbackRequest.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(callbackRequest, callbackResponse, TEST_SECRET);
        assertThat(domain, is(TEST_DOMAIN));
    }
}
