package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.auth.AuthorizeUrlBuilder;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwk.JwkProvider;
import com.auth0.net.Telemetry;
import com.auth0.net.TokenRequest;
import com.auth0.net.Request;
import com.auth0.net.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Cookie;

import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SuppressWarnings("deprecated")
public class AuthenticationControllerTest {

    @Mock
    private AuthAPI client;
    @Mock
    private IdTokenVerifier.Options verificationOptions;
    @Captor
    private ArgumentCaptor<SignatureVerifier> signatureVerifierCaptor;

    private AuthenticationController.Builder builderSpy;

    @Mock
    private HttpServletRequest request; // Mockito mock for HttpServletRequest
    @Mock
    private HttpSession session; // Mockito mock for HttpSession
    private CustomMockHttpServletResponse response; // Instance of your custom mock response

    private Map<String, Object> sessionAttributes;

    private static MockedStatic<RandomStorage> mockedRandomStorage;
    private static MockedStatic<SessionUtils> mockedSessionUtils;


    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        AuthenticationController.Builder builder = AuthenticationController.newBuilder("domain", "clientId", "clientSecret");
        builderSpy = spy(builder);

        //doReturn(client).when(builderSpy).createAPIClient(eq("domain"), eq("clientId"), eq("clientSecret"), eq(null));
        doReturn(verificationOptions).when(builderSpy).createIdTokenVerificationOptions(eq("https://domain/"), eq("clientId"), signatureVerifierCaptor.capture());
        doReturn("1.2.3").when(builderSpy).obtainPackageVersion();

        sessionAttributes = new HashMap<>();

        when(request.getScheme()).thenReturn("https");
        when(request.getServerName()).thenReturn("localhost"); // Consistent server name for mocking
        when(request.getServerPort()).thenReturn(8080); // Consistent port
        when(request.getRequestURI()).thenReturn("/callback");
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://localhost:8080/callback"));

    }

    @BeforeAll
    public static void setUpStaticMocks() {
        // Mock RandomStorage static methods
        mockedRandomStorage = Mockito.mockStatic(RandomStorage.class);
        mockedRandomStorage.when(() -> RandomStorage.setSessionState(any(HttpServletRequest.class), anyString()))
                .thenAnswer(invocation -> null);
        mockedRandomStorage.when(() -> RandomStorage.setSessionNonce(any(HttpServletRequest.class), anyString()))
                .thenAnswer(invocation -> null);
        mockedRandomStorage.when(() -> RandomStorage.removeSessionNonce(any(HttpServletRequest.class)))
                .thenReturn("mockedNonce");

        // Mock SessionUtils static methods
        mockedSessionUtils = Mockito.mockStatic(SessionUtils.class);
        mockedSessionUtils.when(() -> SessionUtils.set(any(HttpServletRequest.class), anyString(), any()))
                .thenAnswer(invocation -> null);
        mockedSessionUtils.when(() -> SessionUtils.remove(any(HttpServletRequest.class), anyString()))
                .thenReturn("mockedValue");
    }

    @AfterAll
    public static void tearDownStaticMocks() {
        // Close the static mocks to deregister them
        if (mockedRandomStorage != null) {
            mockedRandomStorage.close();
        }
        if (mockedSessionUtils != null) {
            mockedSessionUtils.close();
        }
    }

//    @Test
//    public void shouldSetupClientWithTelemetry() {
//        AuthenticationController controller = builderSpy.build();
//
//        ArgumentCaptor<Telemetry> telemetryCaptor = ArgumentCaptor.forClass(Telemetry.class);
//
//        assertThat(controller, is(notNullValue()));
//        RequestProcessor requestProcessor = controller.getRequestProcessor();
//        assertThat(requestProcessor.getClient(), is(client));
//        verify(client).setTelemetry(telemetryCaptor.capture());
//
//        Telemetry capturedTelemetry = telemetryCaptor.getValue();
//        assertThat(capturedTelemetry, is(notNullValue()));
//        assertThat(capturedTelemetry.getName(), is("auth0-java-mvc-common"));
//        assertThat(capturedTelemetry.getVersion(), is("1.2.3"));
//    }

//    @Test
//    public void shouldCreateAuthAPIClientWithoutCustomHttpOptions() {
//        ArgumentCaptor<HttpOptions> captor = ArgumentCaptor.forClass(HttpOptions.class);
//        AuthenticationController.Builder spy = spy(AuthenticationController.newBuilder("domain", "clientId", "clientSecret"));
//
//        spy.build();
//        verify(spy).createAPIClient(eq("domain"), eq("clientId"), eq("clientSecret"), captor.capture());
//
//        HttpOptions actual = captor.getValue();
//        assertThat(actual, is(nullValue()));
//
//    }
//
//    @Test
//    public void shouldDisableTelemetry() {
//        AuthenticationController controller = builderSpy.build();
//        controller.doNotSendTelemetry();
//
//        verify(client).doNotSendTelemetry();
//    }
//
//    @Test
//    public void shouldEnableLogging() {
//        AuthenticationController controller = builderSpy.build();
//
//        controller.setLoggingEnabled(true);
//        verify(client).setLoggingEnabled(true);
//    }
//
//    @Test
//    public void shouldDisableLogging() {
//        AuthenticationController controller = builderSpy.build();
//
//        controller.setLoggingEnabled(true);
//        verify(client).setLoggingEnabled(true);
//    }

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
        assertThrows(NullPointerException.class,
                () -> AuthenticationController.newBuilder(null, "clientId", "clientSecret"));
    }

    @Test
    public void shouldThrowOnMissingClientId() {
        assertThrows(NullPointerException.class,
                () -> AuthenticationController.newBuilder("domain", null, "clientSecret"));
    }

    @Test
    public void shouldThrowOnMissingClientSecret() {
        assertThrows(NullPointerException.class,
                () -> AuthenticationController.newBuilder("domain", "clientId", null));
    }

    @Test
    public void shouldThrowOnMissingJwkProvider() {
        assertThrows(NullPointerException.class,
                () -> AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                        .withJwkProvider(null));
    }

    @Test
    public void shouldThrowOnMissingResponseType() {
        assertThrows(NullPointerException.class,
                () -> AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                        .withResponseType(null));
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

        controller.handle(request, response);

        verify(requestProcessor).process(request, response);
    }

    @Test
    public void shouldBuildAuthorizeUriWithRandomStateAndNonce() {
        RequestProcessor requestProcessor = mock(RequestProcessor.class);
        AuthenticationController controller = new AuthenticationController(requestProcessor);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        controller.buildAuthorizeUrl(request, response,"https://redirect.uri/here");

        verify(requestProcessor).buildAuthorizeUrl(eq(request), eq(response), eq("https://redirect.uri/here"), anyString(), anyString());
    }

    @Test
    public void shouldSetLaxCookiesAndNoLegacyCookieWhenCodeFlow() {
        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("code")
                .build();

        controller.buildAuthorizeUrl(mock(HttpServletRequest.class), response, "https://redirect.uri/here")
                .withState("state")
                .build();

        Collection<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(1));
        assertThat(headers, everyItem(is("com.auth0.state=state; HttpOnly; Max-Age=600; SameSite=Lax")));
    }

    @Test
    public void shouldSetSameSiteNoneCookiesAndLegacyCookieWhenIdTokenResponse() {
        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .build();

        controller.buildAuthorizeUrl(mock(HttpServletRequest.class), response, "https://redirect.uri/here")
                .withState("state")
                .withNonce("nonce")
                .build();

        Collection<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(4));
        assertThat(headers, hasItem("com.auth0.state=state; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=state; HttpOnly; Max-Age=600"));
        assertThat(headers, hasItem("com.auth0.nonce=nonce; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.nonce=nonce; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetSameSiteNoneCookiesAndNoLegacyCookieWhenIdTokenResponse() {
        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .withLegacySameSiteCookie(false)
                .build();

        controller.buildAuthorizeUrl(mock(HttpServletRequest.class), response, "https://redirect.uri/here")
                .withState("state")
                .withNonce("nonce")
                .build();

        Collection<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(2));
        assertThat(headers, hasItem("com.auth0.state=state; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("com.auth0.nonce=nonce; HttpOnly; Max-Age=600; SameSite=None; Secure"));
    }

    @Test
    public void shouldCheckSessionFallbackWhenHandleCalledWithRequestAndResponse() throws Exception {
        // Build the controller with a mocked RequestProcessor
        RequestProcessor requestProcessor = mock(RequestProcessor.class);
        AuthenticationController controller = new AuthenticationController(requestProcessor);

        // Mock TokenRequest and its behavior
        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        Response<TokenHolder> tokenResponse = mock(Response.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);

        when(codeExchangeRequest.execute()).thenReturn(tokenResponse);
        when(tokenResponse.getBody()).thenReturn(tokenHolder);
        when(client.exchangeCode("abc123", "http://localhost")).thenReturn(codeExchangeRequest);

        // Mock AuthorizeUrlBuilder
        AuthorizeUrlBuilder mockBuilder = mock(AuthorizeUrlBuilder.class);
        when(mockBuilder.withResponseType("code")).thenReturn(mockBuilder);
        when(mockBuilder.withScope("openid")).thenReturn(mockBuilder);
        when(client.authorizeUrl("https://redirect.uri/here")).thenReturn(mockBuilder);

        // Mock HttpServletRequest and HttpSession
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);

        when(session.getAttribute("com.auth0.state")).thenReturn("state");
        when(session.getAttribute("com.auth0.nonce")).thenReturn("nonce");

        // Add state as a cookie
        Cookie stateCookie = new Cookie("com.auth0.state", "state");
        when(request.getCookies()).thenReturn(new Cookie[]{stateCookie});

        // Set request parameters
        when(request.getParameter("state")).thenReturn("state");
        when(request.getParameter("nonce")).thenReturn("nonce");
        when(request.getParameter("code")).thenReturn("abc123");

        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        // Mock the RequestProcessor's process method
        when(requestProcessor.process(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn(null);

        // Call the handle method and verify the process method is invoked
        controller.handle(request, response);
        verify(requestProcessor).process(request, response);
    }

    @Test
    public void shouldAllowOrganizationParameter() {
        AuthenticationController controller = AuthenticationController.newBuilder("DOMAIN", "CLIENT_ID", "SECRET")
                .withOrganization("orgId_abc123")
                .build();

        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        String authUrl = controller.buildAuthorizeUrl(mock(HttpServletRequest.class), response, "https://me.com/redirect")
                .build();
        assertThat(authUrl, containsString("organization=orgId_abc123"));
    }

    @Test
    public void shouldThrowOnNullOrganizationParameter() {
        assertThrows(NullPointerException.class,
                () -> AuthenticationController.newBuilder("DOMAIN", "CLIENT_ID", "SECRET")
                        .withOrganization(null));
    }

    @Test
    public void shouldAllowInvitationParameter() {
        AuthenticationController controller = AuthenticationController.newBuilder("DOMAIN", "CLIENT_ID", "SECRET")
                .withInvitation("invitation_123")
                .build();

        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());

        String authUrl = controller.buildAuthorizeUrl(mock(HttpServletRequest.class), response, "https://me.com/redirect")
                .build();
        assertThat(authUrl, containsString("invitation=invitation_123"));
    }

    @Test
    public void shouldThrowOnNullInvitationParameter() {
        assertThrows(NullPointerException.class,
                () -> AuthenticationController.newBuilder("DOMAIN", "CLIENT_ID", "SECRET")
                        .withInvitation(null));
    }

    @Test
    public void shouldConfigureCookiePath() {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withCookiePath("/Path")
                .build();

        HttpServletResponse response = new CustomMockHttpServletResponse(new CustomMockHttpServletResponse.BasicHttpServletResponse());


        controller.buildAuthorizeUrl(mock(HttpServletRequest.class), response, "https://redirect.uri/here")
                .withState("state")
                .build();

        Collection<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(1));
        assertThat(headers, everyItem(is("com.auth0.state=state; HttpOnly; Max-Age=600; Path=/Path; SameSite=Lax")));
    }


}
