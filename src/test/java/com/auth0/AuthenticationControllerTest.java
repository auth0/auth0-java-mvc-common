package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import com.auth0.net.Telemetry;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class AuthenticationControllerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private AuthAPI client;

    private AuthenticationController.Builder builderSpy;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        AuthenticationController.Builder builder = AuthenticationController.newBuilder("domain", "clientId", "clientSecret");
        builderSpy = spy(builder);

        doReturn(client).when(builderSpy).createAPIClient(eq("domain"), eq("clientId"), eq("clientSecret"));
        doReturn("1.2.3").when(builderSpy).obtainPackageVersion();
    }

    @Test
    public void shouldSetupClientWithTelemetry() {
        AuthenticationController controller = builderSpy.build();

        ArgumentCaptor<Telemetry> telemetryCaptor = ArgumentCaptor.forClass(Telemetry.class);

        assertThat(controller, is(notNullValue()));
        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.getClient(), is(client));
        verify(client).setTelemetry(telemetryCaptor.capture());

        Telemetry capturedTelemetry = telemetryCaptor.getValue();
        assertThat(capturedTelemetry, is(notNullValue()));
        assertThat(capturedTelemetry.getName(), is("auth0-java-mvc-common"));
        assertThat(capturedTelemetry.getVersion(), is("1.2.3"));
    }

    @Test
    public void shouldDisableTelemetry() {
        AuthenticationController controller = builderSpy.build();
        controller.doNotSendTelemetry();

        verify(client).doNotSendTelemetry();
    }

    @Test
    public void shouldEnableLogging() {
        AuthenticationController controller = builderSpy.build();

        controller.setLoggingEnabled(true);
        verify(client).setLoggingEnabled(true);
    }

    @Test
    public void shouldDisableLogging() {
        AuthenticationController controller = builderSpy.build();

        controller.setLoggingEnabled(true);
        verify(client).setLoggingEnabled(true);
    }

    @Test
    public void shouldThrowOnMissingDomain() {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder(null, "clientId", "clientSecret");
    }

    @Test
    public void shouldThrowOnMissingClientId() {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", null, "clientSecret");
    }

    @Test
    public void shouldThrowOnMissingClientSecret() {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", "clientId", null);
    }

    @Test
    public void shouldThrowOnMissingJwkProvider() {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withJwkProvider(null);
    }

    @Test
    public void shouldThrowOnMissingResponseType() {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType(null);
    }

    @Test
    public void shouldCreateWithDefaultValues() {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .build();

        assertThat(controller, is(notNullValue()));
        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.getResponseType(), contains("code"));
        assertThat(requestProcessor.verifyOptions.audience, is("clientId"));
        assertThat(requestProcessor.verifyOptions.issuer, is("domain"));
        assertThat(requestProcessor.verifyOptions.verifier, is(notNullValue()));

        assertThat(requestProcessor.verifyOptions.leeway, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.clock, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.nonce, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.maxAge, is(nullValue()));
    }

    @Test
    public void shouldCreateWithResponseType() {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("toKEn Id_TokEn cOdE")
                .build();

        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.getResponseType(), contains("token", "id_token", "code"));
    }

    @Test
    public void shouldCreateWithJwkProvider() {
        JwkProvider provider = mock(JwkProvider.class);
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withJwkProvider(provider)
                .build();
    }

    @Test
    public void shouldCreateWithIDTokenVerificationLeeway() {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withIdTokenVerificationLeeway(12345)
                .build();

        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.verifyOptions.leeway, is(12345));
    }

    @Test
    public void shouldCreateWithMaxAge() {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withAuthenticationMaxAge(12345)
                .build();

        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.verifyOptions.maxAge, is(12345));
    }

    @Test
    public void shouldProcessRequest() throws IdentityVerificationException {
        RequestProcessor requestProcessor = mock(RequestProcessor.class);
        AuthenticationController controller = new AuthenticationController(requestProcessor);

        HttpServletRequest req = new MockHttpServletRequest();
        controller.handle(req);

        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldBuildAuthorizeUriWithRandomStateAndNonce() {
        RequestProcessor requestProcessor = mock(RequestProcessor.class);
        AuthenticationController controller = new AuthenticationController(requestProcessor);

        HttpServletRequest req = new MockHttpServletRequest();
        controller.buildAuthorizeUrl(req, "https://redirect.uri/here");

        verify(requestProcessor).buildAuthorizeUrl(eq(req), eq("https://redirect.uri/here"), anyString(), anyString());
    }

}