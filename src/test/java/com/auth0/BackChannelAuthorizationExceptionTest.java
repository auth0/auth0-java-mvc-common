package com.auth0;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class BackChannelAuthorizationExceptionTest {

    @Test
    public void shouldIdentifyAuthorizationPending() {
        BackChannelAuthorizationException e = new BackChannelAuthorizationException(
                BackChannelAuthorizationException.AUTHORIZATION_PENDING, "pending");
        assertThat(e.isAuthorizationPending(), is(true));
        assertThat(e.isSlowDown(), is(false));
        assertThat(e.isExpiredToken(), is(false));
        assertThat(e.isAccessDenied(), is(false));
        assertThat(e.getCode(), is("authorization_pending"));
    }

    @Test
    public void shouldIdentifySlowDown() {
        BackChannelAuthorizationException e = new BackChannelAuthorizationException(
                BackChannelAuthorizationException.SLOW_DOWN, "slow down");
        assertThat(e.isSlowDown(), is(true));
        assertThat(e.isAuthorizationPending(), is(false));
    }

    @Test
    public void shouldIdentifyExpiredToken() {
        BackChannelAuthorizationException e = new BackChannelAuthorizationException(
                BackChannelAuthorizationException.EXPIRED_TOKEN, "expired");
        assertThat(e.isExpiredToken(), is(true));
    }

    @Test
    public void shouldIdentifyAccessDenied() {
        BackChannelAuthorizationException e = new BackChannelAuthorizationException(
                BackChannelAuthorizationException.ACCESS_DENIED, "denied");
        assertThat(e.isAccessDenied(), is(true));
    }

    @Test
    public void shouldBeIdentityVerificationException() {
        BackChannelAuthorizationException e = new BackChannelAuthorizationException(
                BackChannelAuthorizationException.ACCESS_DENIED, "denied");
        assertThat(e instanceof IdentityVerificationException, is(true));
    }
}
