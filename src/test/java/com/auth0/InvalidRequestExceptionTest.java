package com.auth0;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class InvalidRequestExceptionTest {

    private InvalidRequestException exception;

    @BeforeEach
    public void setUp() {
        exception = new InvalidRequestException("error", "message");
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldGetDescription() {
        assertThat(exception.getDescription(), is("message"));
    }

    @Test
    public void shouldGetCode() {
        assertThat(exception.getCode(), is("error"));
    }

}
