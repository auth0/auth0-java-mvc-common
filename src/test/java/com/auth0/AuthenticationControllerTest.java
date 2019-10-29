package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import com.auth0.net.Telemetry;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.*;

public class AuthenticationControllerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private AuthAPI client;
    @Mock
    private IdTokenVerifier.Options verificationOptions;
    @Captor
    private ArgumentCaptor<SignatureVerifier> signatureVerifierCaptor;

    private AuthenticationController.Builder builderSpy;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        AuthenticationController.Builder builder = AuthenticationController.newBuilder("domain", "clientId", "clientSecret");
        builderSpy = spy(builder);

        doReturn(client).when(builderSpy).createAPIClient(eq("domain"), eq("clientId"), eq("clientSecret"));
        doReturn(verificationOptions).when(builderSpy).createIdTokenVerificationOptions(eq("https://domain/"), eq("clientId"), signatureVerifierCaptor.capture());
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
    public void shouldCreateWithSymmetricSignatureVerifierForNoCodeGrants() {
        AuthenticationController controller = builderSpy
                .withResponseType("id_token")
                .build();

        SignatureVerifier signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(SymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("token")
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(SymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));
    }

    @Test
    public void shouldCreateWithAsymmetricSignatureVerifierWhenJwkProviderIsExplicitlySet() {
        JwkProvider jwkProvider = mock(JwkProvider.class);
        AuthenticationController controller = builderSpy
                .withResponseType("code id_token")
                .withJwkProvider(jwkProvider)
                .build();

        SignatureVerifier signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AsymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("code token")
                .withJwkProvider(jwkProvider)
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AsymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("code id_token token")
                .withJwkProvider(jwkProvider)
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AsymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("code")
                .withJwkProvider(jwkProvider)
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AsymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("id_token")
                .withJwkProvider(jwkProvider)
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AsymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("token")
                .withJwkProvider(jwkProvider)
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AsymmetricSignatureVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));
    }

    @Test
    public void shouldCreateWithAlgorithmNameSignatureVerifierForResponseTypesIncludingCode() {
        AuthenticationController controller = builderSpy
                .withResponseType("code id_token")
                .build();

        SignatureVerifier signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AlgorithmNameVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("code token")
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AlgorithmNameVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("code token id_token")
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AlgorithmNameVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));

        controller = builderSpy
                .withResponseType("code")
                .build();

        signatureVerifier = signatureVerifierCaptor.getValue();
        assertThat(signatureVerifier, is(notNullValue()));
        assertThat(signatureVerifier, instanceOf(AlgorithmNameVerifier.class));
        assertThat(verificationOptions, is(controller.getRequestProcessor().verifyOptions));
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
        assertThat(requestProcessor.verifyOptions.issuer, is("https://domain/"));
        assertThat(requestProcessor.verifyOptions.verifier, is(notNullValue()));

        assertThat(requestProcessor.verifyOptions.clockSkew, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.clock, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.nonce, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.getMaxAge(), is(nullValue()));
    }

    @Test
    public void shouldHandleHttpDomain() {
        AuthenticationController controller = AuthenticationController.newBuilder("http://domain/", "clientId", "clientSecret")
                .build();

        assertThat(controller, is(notNullValue()));
        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.getResponseType(), contains("code"));
        assertThat(requestProcessor.verifyOptions.audience, is("clientId"));
        assertThat(requestProcessor.verifyOptions.issuer, is("http://domain/"));
        assertThat(requestProcessor.verifyOptions.verifier, is(notNullValue()));

        assertThat(requestProcessor.verifyOptions.clockSkew, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.clock, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.nonce, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.getMaxAge(), is(nullValue()));
    }

    @Test
    public void shouldHandleHttpsDomain() {
        AuthenticationController controller = AuthenticationController.newBuilder("https://domain/", "clientId", "clientSecret")
                .build();

        assertThat(controller, is(notNullValue()));
        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.getResponseType(), contains("code"));
        assertThat(requestProcessor.verifyOptions.audience, is("clientId"));
        assertThat(requestProcessor.verifyOptions.issuer, is("https://domain/"));
        assertThat(requestProcessor.verifyOptions.verifier, is(notNullValue()));

        assertThat(requestProcessor.verifyOptions.clockSkew, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.clock, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.nonce, is(nullValue()));
        assertThat(requestProcessor.verifyOptions.getMaxAge(), is(nullValue()));
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
                .withClockSkew(12345)
                .build();

        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.verifyOptions.clockSkew, is(12345));
    }

    @Test
    public void shouldCreateWithMaxAge() {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withAuthenticationMaxAge(12345)
                .build();

        RequestProcessor requestProcessor = controller.getRequestProcessor();
        assertThat(requestProcessor.verifyOptions.getMaxAge(), is(12345));
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