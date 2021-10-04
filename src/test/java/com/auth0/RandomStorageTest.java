package com.auth0;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class RandomStorageTest {

    @Test
    public void shouldSetState() {
        MockHttpServletRequest req = new MockHttpServletRequest();

        RandomStorage.setSessionState(req, "123456");
        assertThat(req.getSession().getAttribute("com.auth0.state"), is("123456"));
    }

    @Test
    public void shouldAcceptBothNullStates() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        boolean validState = RandomStorage.checkSessionState(req, null);
        assertThat(validState, is(true));
    }

    @Test
    public void shouldCheckAndRemoveInvalidState() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.state", "123456");

        boolean validState = RandomStorage.checkSessionState(req, "abcdef");
        assertThat(validState, is(false));
        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldCheckAndRemoveCorrectState() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.state", "123456");

        boolean validState = RandomStorage.checkSessionState(req, "123456");
        assertThat(validState, is(true));
        assertThat(req.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldSetNonce() {
        MockHttpServletRequest req = new MockHttpServletRequest();

        RandomStorage.setSessionNonce(req, "123456");
        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is("123456"));
    }

    @Test
    public void shouldGetAndRemoveNonce() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("com.auth0.nonce", "123456");

        String nonce = RandomStorage.removeSessionNonce(req);
        assertThat(nonce, is("123456"));
        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }

    @Test
    public void shouldGetAndRemoveNonceIfMissing() {
        MockHttpServletRequest req = new MockHttpServletRequest();

        String nonce = RandomStorage.removeSessionNonce(req);
        assertThat(nonce, is(nullValue()));
        assertThat(req.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }
}
