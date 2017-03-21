package com.auth0;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class IdentityVerificationExceptionTest {
    private Throwable cause;
    private IdentityVerificationException exception;

    @Before
    public void setUp() throws Exception {
        cause = mock(Throwable.class);
        exception = new IdentityVerificationException("error", "description", cause);
    }

    @Test
    public void shouldGetCode() throws Exception {
        assertThat(exception.getCode(), is("error"));
    }

    @Test
    public void shouldGetDescription() throws Exception {
        assertThat(exception.getMessage(), is("description"));
    }

    @Test
    public void shouldGetCause() throws Exception {
        assertThat(exception.getCause(), is(cause));
    }

    @Test
    public void shouldBeAPIError() throws Exception {
        IdentityVerificationException exception = new IdentityVerificationException("a0.api_error", "description", null);
        assertThat(exception.isAPIError(), is(true));
    }

    @Test
    public void shouldBeJWTError() throws Exception {
        IdentityVerificationException exception = new IdentityVerificationException("a0.missing_jwt_public_key_error", "description", null);
        assertThat(exception.isJWTError(), is(true));
        IdentityVerificationException exception2 = new IdentityVerificationException("a0.invalid_jwt_error", "description", null);
        assertThat(exception2.isJWTError(), is(true));
    }
}