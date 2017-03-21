package com.auth0;

import com.auth0.jwk.JwkProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class RequestProcessorFactoryTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private RequestProcessorFactory factory;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        factory = new RequestProcessorFactory();
    }

    @Test
    public void shouldCreateForCodeGrant() throws Exception {
        RequestProcessor processor = factory.forCodeGrant("domain", "clientId", "clientSecret", "responseType");
        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(notNullValue()));
        assertThat(processor.responseType, is("responseType"));
        assertThat(processor.verifier, is(nullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantHS() throws Exception {
        RequestProcessor processor = factory.forImplicitGrant("domain", "clientId", "clientSecret", "responseType");
        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(notNullValue()));
        assertThat(processor.responseType, is("responseType"));
        assertThat(processor.verifier, is(notNullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantRS() throws Exception {
        JwkProvider jwkProvider = mock(JwkProvider.class);
        RequestProcessor processor = factory.forImplicitGrant("domain", "clientId", "clientSecret", "responseType", jwkProvider);
        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(notNullValue()));
        assertThat(processor.responseType, is("responseType"));
        assertThat(processor.verifier, is(notNullValue()));
    }

}