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
}
