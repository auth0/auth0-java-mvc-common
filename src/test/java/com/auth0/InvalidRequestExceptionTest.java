package com.auth0;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class InvalidRequestExceptionTest {

    private InvalidRequestException exception;

    @Before
    public void setUp() throws Exception {
        exception = new InvalidRequestException("error", "message");
    }

    @Test
    public void shouldGetDescription() throws Exception {
        assertThat(exception.getDescription(), is("message"));
    }

    @Test
    public void shouldGetCode() throws Exception {
        assertThat(exception.getCode(), is("error"));
    }

}