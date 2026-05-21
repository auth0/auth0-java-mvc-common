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
        TransientCookieStore.storeNonce(response, null, "someState", SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

    @Test
    public void shouldNotSetNonceCookieIfStateIsNull() {
        TransientCookieStore.storeNonce(response, "nonceValue", null, SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(0));
    }

    @Test
    public void shouldSetStateCookieWithTransactionKey() {
        TransientCookieStore.storeState(response, "myState123", SameSite.LAX, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        // Cookie name should be "com.auth0.state.myState123"
        assertThat(headers.get(0), containsString("com.auth0.state.myState123=myState123"));
    }

    @Test
    public void shouldSetNonceCookieWithTransactionKey() {
        TransientCookieStore.storeNonce(response, "nonceVal", "myState123", SameSite.LAX, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));
        // Cookie name should be "com.auth0.nonce.myState123"
        assertThat(headers.get(0), containsString("com.auth0.nonce.myState123=nonceVal"));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers.get(0), containsString("com.auth0.state.123456=123456"));
        assertThat(headers.get(0), containsString("SameSite=None"));
        assertThat(headers.get(0), containsString("Secure"));
        assertThat(headers.get(1), containsString("_com.auth0.state.123456=123456"));
    }

    @Test
    public void shouldSetStateSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers.get(0), containsString("com.auth0.state.123456=123456"));
        assertThat(headers.get(0), containsString("SameSite=None"));
    }

    @Test
    public void shouldSetSecureCookieWhenSameSiteLaxAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, true, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers.get(0), containsString("Secure"));
        assertThat(headers.get(0), containsString("SameSite=Lax"));
    }

    @Test
    public void shouldSetSecureFallbackCookieWhenSameSiteNoneAndConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.NONE, true, true, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers.get(0), containsString("SameSite=None"));
        assertThat(headers.get(0), containsString("Secure"));
        assertThat(headers.get(1), containsString("Secure"));
    }

    @Test
    public void shouldNotSetSecureCookieWhenSameSiteLaxAndNotConfigured() {
        TransientCookieStore.storeState(response, "123456", SameSite.LAX, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers.get(0), not(containsString("Secure")));
        assertThat(headers.get(0), containsString("SameSite=Lax"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndFallbackCookie() {
        TransientCookieStore.storeNonce(response, "nonceVal", "stateVal", SameSite.NONE, true, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));

        assertThat(headers.get(0), containsString("com.auth0.nonce.stateVal=nonceVal"));
        assertThat(headers.get(0), containsString("SameSite=None"));
        assertThat(headers.get(1), containsString("_com.auth0.nonce.stateVal=nonceVal"));
    }

    @Test
    public void shouldSetNonceSameSiteCookieAndNoFallbackCookie() {
        TransientCookieStore.storeNonce(response, "nonceVal", "stateVal", SameSite.NONE, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        assertThat(headers.get(0), containsString("com.auth0.nonce.stateVal=nonceVal"));
    }

    // --- State retrieval tests (transaction-keyed) ---

    @Test
    public void shouldRetrieveTransactionKeyedStateCookie() {
        Cookie cookie = new Cookie("com.auth0.state.myState", "myState");
        request.setCookies(cookie);
        request.setParameter("state", "myState");

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("myState"));

        // Should delete the cookie
        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));
        assertThat(cookies[0].getMaxAge(), is(0));
    }

    @Test
    public void shouldFallbackToLegacyFixedStateCookie() {
        // Legacy cookie (from v1 SDK or in-flight transaction during upgrade)
        Cookie cookie = new Cookie("com.auth0.state", "legacyState");
        request.setCookies(cookie);
        request.setParameter("state", "legacyState");

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("legacyState"));
    }

    @Test
    public void shouldPreferTransactionKeyedOverLegacy() {
        Cookie txCookie = new Cookie("com.auth0.state.txState", "txState");
        Cookie legacyCookie = new Cookie("com.auth0.state", "oldState");
        request.setCookies(txCookie, legacyCookie);
        request.setParameter("state", "txState");

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is("txState"));
    }

    @Test
    public void shouldRemoveStateSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.state.123456", "123456");
        Cookie cookie2 = new Cookie("_com.auth0.state.123456", "123456");
        request.setCookies(cookie1, cookie2);
        request.setParameter("state", "123456");

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
    public void shouldReturnNullStateWhenNoCookies() {
        request.setParameter("state", "someState");
        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is(nullValue()));
    }

    @Test
    public void shouldReturnNullStateWhenNoStateParam() {
        // No state parameter in request → null
        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is(nullValue()));
    }

    @Test
    public void shouldReturnEmptyWhenNoStateCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);
        request.setParameter("state", "someState");

        String state = TransientCookieStore.getState(request, response);
        assertThat(state, is(nullValue()));
    }

    @Test
    public void shouldRetrieveTransactionKeyedNonceCookie() {
        Cookie cookie = new Cookie("com.auth0.nonce.myState", "nonceValue");
        request.setCookies(cookie);

        String nonce = TransientCookieStore.getNonce(request, response, "myState");
        assertThat(nonce, is("nonceValue"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));
        assertThat(cookies[0].getMaxAge(), is(0));
    }

    @Test
    public void shouldFallbackToLegacyFixedNonceCookie() {
        Cookie cookie = new Cookie("com.auth0.nonce", "legacyNonce");
        request.setCookies(cookie);

        String nonce = TransientCookieStore.getNonce(request, response, "someState");
        assertThat(nonce, is("legacyNonce"));
    }

    @Test
    public void shouldRemoveNonceSameSiteCookieAndFallbackCookie() {
        Cookie cookie1 = new Cookie("com.auth0.nonce.stateVal", "nonceVal");
        Cookie cookie2 = new Cookie("_com.auth0.nonce.stateVal", "nonceVal");
        request.setCookies(cookie1, cookie2);

        String nonce = TransientCookieStore.getNonce(request, response, "stateVal");
        assertThat(nonce, is("nonceVal"));

        Cookie[] cookies = response.getCookies();
        assertThat(cookies, is(notNullValue()));

        List<Cookie> cookieList = Arrays.asList(cookies);
        assertThat(cookieList.size(), is(2));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("value", is(""))));
        assertThat(Arrays.asList(cookies), everyItem(HasPropertyWithValue.hasProperty("maxAge", is(0))));
    }

    @Test
    public void shouldReturnNullNonceWhenNoCookies() {
        String nonce = TransientCookieStore.getNonce(request, response, "someState");
        assertThat(nonce, is(nullValue()));
    }

    @Test
    public void shouldReturnNullNonceWhenStateIsNull() {
        String nonce = TransientCookieStore.getNonce(request, response, null);
        assertThat(nonce, is(nullValue()));
    }

    @Test
    public void shouldReturnNullWhenNoNonceCookie() {
        Cookie cookie1 = new Cookie("someCookie", "123456");
        request.setCookies(cookie1);

        String nonce = TransientCookieStore.getNonce(request, response, "someState");
        assertThat(nonce, is(nullValue()));
    }

    @Test
    public void shouldIsolateMultipleTransactions() {
        // Simulate two tabs storing state cookies
        TransientCookieStore.storeState(response, "stateA", SameSite.LAX, false, false, null);
        TransientCookieStore.storeState(response, "stateB", SameSite.LAX, false, false, null);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2));
        assertThat(headers.get(0), containsString("com.auth0.state.stateA=stateA"));
        assertThat(headers.get(1), containsString("com.auth0.state.stateB=stateB"));
    }

    @Test
    public void shouldRetrieveCorrectStateForEachTransaction() {
        // Both transaction cookies exist
        Cookie cookieA = new Cookie("com.auth0.state.stateA", "stateA");
        Cookie cookieB = new Cookie("com.auth0.state.stateB", "stateB");
        request.setCookies(cookieA, cookieB);

        // Tab A callback
        request.setParameter("state", "stateA");
        String stateA = TransientCookieStore.getState(request, response);
        assertThat(stateA, is("stateA"));

        // Tab B callback (new request)
        MockHttpServletRequest requestB = new MockHttpServletRequest();
        MockHttpServletResponse responseB = new MockHttpServletResponse();
        requestB.setCookies(cookieA, cookieB);
        requestB.setParameter("state", "stateB");
        String stateB = TransientCookieStore.getState(requestB, responseB);
        assertThat(stateB, is("stateB"));
    }

    @Test
    public void shouldNotDeleteOtherTransactionCookies() {
        Cookie cookieA = new Cookie("com.auth0.state.stateA", "stateA");
        Cookie cookieB = new Cookie("com.auth0.state.stateB", "stateB");
        request.setCookies(cookieA, cookieB);
        request.setParameter("state", "stateA");

        TransientCookieStore.getState(request, response);

        // Only stateA's cookie should be deleted
        Cookie[] deletedCookies = response.getCookies();
        assertThat(deletedCookies.length, is(1));
        assertThat(deletedCookies[0].getName(), is("com.auth0.state.stateA"));
        assertThat(deletedCookies[0].getMaxAge(), is(0));
    }

    // --- Origin domain tests ---

    private static final String TEST_SECRET = "testClientSecret123";
    private static final String TEST_DOMAIN = "tenant-a.auth0.com";
    private static final String TEST_STATE = "abc123state";

    @Test
    public void shouldStoreSignedOriginDomainCookie() {
        TransientCookieStore.storeSignedOriginDomain(response, TEST_DOMAIN, TEST_STATE,
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
        TransientCookieStore.storeSignedOriginDomain(response, TEST_DOMAIN, TEST_STATE,
                SameSite.NONE, null, false, TEST_SECRET);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(2)); // primary + legacy fallback
        assertThat(headers.get(0), containsString("SameSite=None"));
        assertThat(headers.get(0), containsString("Secure"));
    }

    @Test
    public void shouldRetrieveAndVerifySignedOriginDomain() {
        String signedValue = SignedCookieUtils.sign(TEST_DOMAIN, TEST_STATE, TEST_SECRET);
        Cookie cookie = new Cookie("com.auth0.origin_domain", signedValue);
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_STATE, TEST_SECRET);
        assertThat(domain, is(TEST_DOMAIN));
    }

    @Test
    public void shouldReturnNullForTamperedOriginDomain() {
        Cookie cookie = new Cookie("com.auth0.origin_domain",
                "evil.auth0.com|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_STATE, TEST_SECRET);
        assertThat(domain, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForMissingOriginDomainCookie() {
        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_STATE, TEST_SECRET);
        assertThat(domain, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForWrongSecret() {
        String signedValue = SignedCookieUtils.sign(TEST_DOMAIN, TEST_STATE, TEST_SECRET);
        Cookie cookie = new Cookie("com.auth0.origin_domain", signedValue);
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_STATE, "wrong-secret");
        assertThat(domain, is(nullValue()));
    }

    @Test
    public void shouldReturnNullForWrongState() {
        String signedValue = SignedCookieUtils.sign(TEST_DOMAIN, TEST_STATE, TEST_SECRET);
        Cookie cookie = new Cookie("com.auth0.origin_domain", signedValue);
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, "different-state", TEST_SECRET);
        assertThat(domain, is(nullValue()));
    }

    @Test
    public void shouldDeleteOriginDomainCookieAfterReading() {
        String signedValue = SignedCookieUtils.sign(TEST_DOMAIN, TEST_STATE, TEST_SECRET);
        Cookie cookie = new Cookie("com.auth0.origin_domain", signedValue);
        request.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(request, response, TEST_STATE, TEST_SECRET);
        assertThat(domain, is(TEST_DOMAIN));

        Cookie[] responseCookies = response.getCookies();
        assertThat(responseCookies, is(notNullValue()));
        boolean foundDeleted = false;
        for (Cookie c : responseCookies) {
            if (c.getName().equals("com.auth0.origin_domain")) {
                assertThat(c.getMaxAge(), is(0));
                assertThat(c.getValue(), is(""));
                foundDeleted = true;
            }
        }
        assertThat(foundDeleted, is(true));
    }

    @Test
    public void shouldStoreAndRetrieveSignedOriginDomainEndToEnd() {
        TransientCookieStore.storeSignedOriginDomain(response, TEST_DOMAIN, TEST_STATE,
                SameSite.LAX, null, false, TEST_SECRET);

        List<String> headers = response.getHeaders("Set-Cookie");
        assertThat(headers.size(), is(1));

        String header = headers.get(0);
        String cookieValue = header.split(";")[0].split("=", 2)[1];

        Cookie cookie = new Cookie("com.auth0.origin_domain", cookieValue);

        MockHttpServletRequest callbackRequest = new MockHttpServletRequest();
        MockHttpServletResponse callbackResponse = new MockHttpServletResponse();
        callbackRequest.setCookies(cookie);

        String domain = TransientCookieStore.getSignedOriginDomain(callbackRequest, callbackResponse, TEST_STATE, TEST_SECRET);
        assertThat(domain, is(TEST_DOMAIN));
    }
}
