package com.auth0;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

public class IdentityVerificationExceptionTest {
    private Throwable cause;
    private IdentityVerificationException exception;

    @BeforeEach
    public void setUp() {
        cause = mock(Throwable.class);
        exception = new IdentityVerificationException("error", "description", cause);
    }

    @Test
    public void shouldGetCode() {
        assertThat(exception.getCode(), is("error"));
    }

    @Test
    public void shouldGetDescription() {
        assertThat(exception.getMessage(), is("description"));
    }

    @Test
    public void shouldGetCause() {
        assertThat(exception.getCause(), is(cause));
    }

    @Test
    public void shouldBeAPIError() {
        IdentityVerificationException exception = new IdentityVerificationException("a0.api_error", "description", null);
        assertThat(exception.isAPIError(), is(true));
    }

    @Test
    public void shouldBeJWTError() {
        IdentityVerificationException exception = new IdentityVerificationException("a0.missing_jwt_public_key_error", "description", null);
        assertThat(exception.isJWTError(), is(true));
        IdentityVerificationException exception2 = new IdentityVerificationException("a0.invalid_jwt_error", "description", null);
        assertThat(exception2.isJWTError(), is(true));
    }
}
