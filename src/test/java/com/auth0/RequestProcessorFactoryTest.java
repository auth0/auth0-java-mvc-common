package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import com.auth0.net.Telemetry;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

public class RequestProcessorFactoryTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private RequestProcessorFactory factorySpy;
    private ArgumentCaptor<AuthAPI> clientCaptor;

    @Before
    public void setUp() {
        RequestProcessorFactory factory = new RequestProcessorFactory();
        factorySpy = Mockito.spy(factory);
        clientCaptor = ArgumentCaptor.forClass(AuthAPI.class);
    }

    @Test
    public void shouldCreateForCodeGrant() {
        RequestProcessor processor = factorySpy.forCodeGrant("domain", "clientId", "clientSecret", "responseType");
        verify(factorySpy).setupTelemetry(clientCaptor.capture());
        AuthAPI capturedClient = clientCaptor.getValue();
        assertThat(capturedClient, is(notNullValue()));

        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(capturedClient));
        assertThat(processor.responseType, is("responseType"));
        assertThat(processor.verifier, is(notNullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantHS() throws Exception {
        RequestProcessor processor = factorySpy.forImplicitGrant("domain", "clientId", "clientSecret", "responseType");
        verify(factorySpy).setupTelemetry(clientCaptor.capture());
        AuthAPI capturedClient = clientCaptor.getValue();
        assertThat(capturedClient, is(notNullValue()));

        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(capturedClient));
        assertThat(processor.responseType, is("responseType"));
        assertThat(processor.verifier, is(notNullValue()));
    }

    @Test
    public void shouldCreateForImplicitGrantRS() {
        JwkProvider jwkProvider = mock(JwkProvider.class);
        RequestProcessor processor = factorySpy.forImplicitGrant("domain", "clientId", "clientSecret", "responseType", jwkProvider);
        verify(factorySpy).setupTelemetry(clientCaptor.capture());
        AuthAPI capturedClient = clientCaptor.getValue();
        assertThat(capturedClient, is(notNullValue()));

        assertThat(processor, is(notNullValue()));
        assertThat(processor.client, is(capturedClient));
        assertThat(processor.responseType, is("responseType"));
        assertThat(processor.verifier, is(notNullValue()));
    }

    @Test
    public void shouldSetupAClientWithTelemetry() {
        ArgumentCaptor<Telemetry> telemetryCaptor = ArgumentCaptor.forClass(Telemetry.class);
        AuthAPI client = mock(AuthAPI.class);
        when(factorySpy.obtainPackageVersion()).thenReturn("1.2.3");
        factorySpy.setupTelemetry(client);

        verify(client).setTelemetry(telemetryCaptor.capture());
        Telemetry capturedTelemetry = telemetryCaptor.getValue();
        assertThat(capturedTelemetry, is(notNullValue()));
        assertThat(capturedTelemetry.getName(), is("auth0-java-mvc-common"));
        assertThat(capturedTelemetry.getVersion(), is("1.2.3"));
    }

}