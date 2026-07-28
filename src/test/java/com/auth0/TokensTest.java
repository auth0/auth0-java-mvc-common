package com.auth0;

import org.junit.jupiter.api.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class TokensTest {

    @Test
    public void shouldReturnValidTokens() {
        Tokens tokens = new Tokens("accessToken", "idToken", "refreshToken", "bearer", 360000L);
        assertThat(tokens.getAccessToken(), is("accessToken"));
        assertThat(tokens.getIdToken(), is("idToken"));
        assertThat(tokens.getRefreshToken(), is("refreshToken"));
        assertThat(tokens.getType(), is("bearer"));
        assertThat(tokens.getExpiresIn(), is(360000L));
        assertThat(tokens.getDomain(), is(nullValue()));
        assertThat(tokens.getIssuer(), is(nullValue()));
    }

    @Test
    public void shouldReturnMissingTokens() {
        Tokens tokens = new Tokens(null, null, null, null, null);
        assertThat(tokens.getAccessToken(), is(nullValue()));
        assertThat(tokens.getIdToken(), is(nullValue()));
        assertThat(tokens.getRefreshToken(), is(nullValue()));
        assertThat(tokens.getType(), is(nullValue()));
        assertThat(tokens.getExpiresIn(), is(nullValue()));
        assertThat(tokens.getDomain(), is(nullValue()));
        assertThat(tokens.getIssuer(), is(nullValue()));
    }

    @Test
    public void shouldHaveNullScopeFromFiveArgConstructor() {
        Tokens tokens = new Tokens("accessToken", "idToken", "refreshToken", "bearer", 360000L);
        assertThat(tokens.getScope(), is(nullValue()));
    }

    @Test
    public void shouldHaveNullScopeFromSevenArgConstructor() {
        Tokens tokens = new Tokens("accessToken", "idToken", "refreshToken", "bearer", 360000L, "domain.auth0.com", "https://domain.auth0.com/");
        assertThat(tokens.getScope(), is(nullValue()));
        assertThat(tokens.getDomain(), is("domain.auth0.com"));
        assertThat(tokens.getIssuer(), is("https://domain.auth0.com/"));
    }

    @Test
    public void shouldReturnScopeFromEightArgConstructor() {
        Tokens tokens = new Tokens("accessToken", "idToken", "refreshToken", "bearer", 360000L, "openid profile", "domain.auth0.com", "https://domain.auth0.com/");
        assertThat(tokens.getAccessToken(), is("accessToken"));
        assertThat(tokens.getIdToken(), is("idToken"));
        assertThat(tokens.getRefreshToken(), is("refreshToken"));
        assertThat(tokens.getType(), is("bearer"));
        assertThat(tokens.getExpiresIn(), is(360000L));
        assertThat(tokens.getScope(), is("openid profile"));
        assertThat(tokens.getDomain(), is("domain.auth0.com"));
        assertThat(tokens.getIssuer(), is("https://domain.auth0.com/"));
    }

    @Test
    public void shouldDefaultSessionExpiresAtToNull() {
        Tokens tokens = new Tokens("at", "it", "rt", "bearer", 3600L, "domain", "issuer");
        assertThat(tokens.getSessionExpiresAt(), is(nullValue()));
    }

    @Test
    public void shouldExposeSessionExpiresAt() {
        long ceiling = nowSeconds() + 3600;
        Tokens tokens = new Tokens("at", "it", "rt", "bearer", 3600L, "scope", "domain", "issuer", ceiling);
        assertThat(tokens.getSessionExpiresAt(), is(ceiling));
    }

    @Test
    public void shouldNotBeExpiredWhenNoCeilingPresent() {
        Tokens tokens = new Tokens("at", "it", "rt", "bearer", 3600L, "scope", "domain", "issuer", null);
        assertThat(tokens.isSessionExpired(), is(false));
        assertThat(tokens.isSessionExpired(0), is(false));
    }

    @Test
    public void shouldNotBeExpiredWhenCeilingIsInFuture() {
        Tokens tokens = new Tokens("at", "it", "rt", "bearer", 3600L, "scope", "domain", "issuer", nowSeconds() + 3600);
        assertThat(tokens.isSessionExpired(), is(false));
    }

    @Test
    public void shouldBeExpiredWhenCeilingHasPassed() {
        Tokens tokens = new Tokens("at", "it", "rt", "bearer", 3600L, "scope", "domain", "issuer", nowSeconds() - 3600);
        assertThat(tokens.isSessionExpired(), is(true));
    }

    @Test
    public void shouldTreatCeilingWithinLeewayAsExpired() {
        // Ceiling 10s in the future, but default 30s leeway pulls it back into the past.
        Tokens tokens = new Tokens("at", "it", "rt", "bearer", 3600L, "scope", "domain", "issuer", nowSeconds() + 10);
        assertThat(tokens.isSessionExpired(), is(true));
        // With no leeway the same ceiling is still in the future.
        assertThat(tokens.isSessionExpired(0), is(false));
    }

    @Test
    public void shouldClampNegativeLeewayToZeroRatherThanExtendingCeiling() {
        // A ceiling 10s in the future. A negative leeway must not push the effective ceiling later
        // (which would report "not expired" past the real ceiling); it is clamped to 0.
        Tokens tokens = new Tokens("at", "it", "rt", "bearer", 3600L, "scope", "domain", "issuer", nowSeconds() + 10);
        assertThat(tokens.isSessionExpired(-3600), is(false));

        // A ceiling 10s in the past: clamped-to-0 leeway still reports expired, not extended.
        Tokens past = new Tokens("at", "it", "rt", "bearer", 3600L, "scope", "domain", "issuer", nowSeconds() - 10);
        assertThat(past.isSessionExpired(-3600), is(true));
    }

    @Test
    public void staticIsSessionExpiredMatchesInstanceBehavior() {
        assertThat(Tokens.isSessionExpired(null, 0), is(false));
        assertThat(Tokens.isSessionExpired(nowSeconds() + 3600, Tokens.DEFAULT_SESSION_EXPIRY_LEEWAY), is(false));
        assertThat(Tokens.isSessionExpired(nowSeconds() - 3600, Tokens.DEFAULT_SESSION_EXPIRY_LEEWAY), is(true));
        // Negative leeway clamped to 0: a future ceiling is not reported expired.
        assertThat(Tokens.isSessionExpired(nowSeconds() + 10, -3600), is(false));
    }

    private static long nowSeconds() {
        return Math.floorDiv(System.currentTimeMillis(), 1000L);
    }
}
