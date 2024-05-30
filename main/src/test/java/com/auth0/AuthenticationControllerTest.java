package com.auth0;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.auth.AuthorizeUrlBuilder;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwk.JwkProvider;
import com.auth0.net.Response;
import com.auth0.net.TokenRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@SuppressWarnings("deprecated")
public class AuthenticationControllerTest {

    @Mock
    private AuthAPI client;
    @Mock
    private IdTokenVerifier.Options verificationOptions;
    @Captor
    private ArgumentCaptor<SignatureVerifier> signatureVerifierCaptor;

    private AuthenticationController.Builder builderSpy;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        AuthenticationController.Builder builder = AuthenticationController.newBuilder("domain", "clientId", "clientSecret");
        builderSpy = spy(builder);

        doReturn(client).when(builderSpy).createAPIClient(eq("domain"), eq("clientId"), eq("clientSecret"));
        doReturn(verificationOptions).when(builderSpy).createIdTokenVerificationOptions(eq("https://domain/"), eq("clientId"), signatureVerifierCaptor.capture());
        doReturn("1.2.3").when(builderSpy).obtainPackageVersion();
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

        HttpServletRequest req = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();

        controller.handle(req, response);

        verify(requestProcessor).process(req, response);
    }

    @Test
    public void shouldBuildAuthorizeUriWithRandomStateAndNonce() {
        RequestProcessor requestProcessor = mock(RequestProcessor.class);
        AuthenticationController controller = new AuthenticationController(requestProcessor);

        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();

        controller.buildAuthorizeUrl(request, response,"https://redirect.uri/here");

        verify(requestProcessor).buildAuthorizeUrl(eq(request), eq(response), eq("https://redirect.uri/here"), anyString(), anyString());
    }

    @Test
    public void shouldSetLaxCookiesAndNoLegacyCookieWhenCodeFlow() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .build();

        controller.buildAuthorizeUrl(new MockHttpServletRequest(), response, "https://redirect.uri/here")
                .withState("state")
                .build();

        List<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(1));
        assertThat(headers, everyItem(is("com.auth0.state=state; HttpOnly; Max-Age=600; SameSite=Lax")));
    }

    @Test
    public void shouldSetSameSiteNoneCookiesAndLegacyCookieWhenIdTokenResponse() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .build();

        controller.buildAuthorizeUrl(new MockHttpServletRequest(), response, "https://redirect.uri/here")
                .withState("state")
                .withNonce("nonce")
                .build();

        List<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(4));
        assertThat(headers, hasItem("com.auth0.state=state; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.state=state; HttpOnly; Max-Age=600"));
        assertThat(headers, hasItem("com.auth0.nonce=nonce; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("_com.auth0.nonce=nonce; HttpOnly; Max-Age=600"));
    }

    @Test
    public void shouldSetSameSiteNoneCookiesAndNoLegacyCookieWhenIdTokenResponse() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .withLegacySameSiteCookie(false)
                .build();

        controller.buildAuthorizeUrl(new MockHttpServletRequest(), response, "https://redirect.uri/here")
                .withState("state")
                .withNonce("nonce")
                .build();

        List<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(2));
        assertThat(headers, hasItem("com.auth0.state=state; HttpOnly; Max-Age=600; SameSite=None; Secure"));
        assertThat(headers, hasItem("com.auth0.nonce=nonce; HttpOnly; Max-Age=600; SameSite=None; Secure"));
    }

    @Test
    public void shouldCheckSessionFallbackWhenHandleCalledWithRequestAndResponse() throws Exception {
        AuthenticationController controller = builderSpy.withResponseType("code").build();

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        Response<TokenHolder> tokenHolderResponse = mock(Response.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolderResponse.getBody()).thenReturn(tokenHolder);
        when(codeExchangeRequest.execute()).thenReturn(tokenHolderResponse);
        when(client.exchangeCode("abc123", "http://localhost")).thenReturn(codeExchangeRequest);

        AuthorizeUrlBuilder mockBuilder = mock(AuthorizeUrlBuilder.class);
        when(mockBuilder.withResponseType("code")).thenReturn(mockBuilder);
        when(mockBuilder.withScope("openid")).thenReturn(mockBuilder);
        when(client.authorizeUrl("https://redirect.uri/here")).thenReturn(mockBuilder);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // build auth URL using deprecated method, which stores state and nonce in session
        String authUrl = controller.buildAuthorizeUrl(request, "https://redirect.uri/here")
                .withState("state")
                .withNonce("nonce")
                .build();

        String state = (String) request.getSession().getAttribute("com.auth0.state");
        String nonce = (String) request.getSession().getAttribute("com.auth0.nonce");
        assertThat(state, is("state"));
        assertThat(nonce, is("nonce"));

        request.setParameter("state", "state");
        request.setParameter("nonce", "nonce");
        request.setParameter("code", "abc123");

        // handle called with request and response, which should use cookies but fallback to session
        controller.handle(request, response);
    }

    @Test
    public void shouldCheckSessionFallbackWhenHandleCalledWithRequest() throws Exception {
        AuthenticationController controller = builderSpy.build();

        TokenRequest codeExchangeRequest = mock(TokenRequest.class);
        Response<TokenHolder> tokenHolderResponse = mock(Response.class);
        TokenHolder tokenHolder = mock(TokenHolder.class);
        when(tokenHolderResponse.getBody()).thenReturn(tokenHolder);
        when(codeExchangeRequest.execute()).thenReturn(tokenHolderResponse);
        when(client.exchangeCode("abc123", "http://localhost")).thenReturn(codeExchangeRequest);

        AuthorizeUrlBuilder mockBuilder = mock(AuthorizeUrlBuilder.class);
        when(mockBuilder.withResponseType("code")).thenReturn(mockBuilder);
        when(mockBuilder.withScope("openid")).thenReturn(mockBuilder);
        when(client.authorizeUrl("https://redirect.uri/here")).thenReturn(mockBuilder);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // build auth URL using request and response, which stores state and nonce in cookies and also session as a fallback
        String authUrl = controller.buildAuthorizeUrl(request, response,"https://redirect.uri/here")
                .withState("state")
                .withNonce("nonce")
                .build();

        String state = (String) request.getSession().getAttribute("com.auth0.state");
        String nonce = (String) request.getSession().getAttribute("com.auth0.nonce");
        assertThat(state, is("state"));
        assertThat(nonce, is("nonce"));

        request.setParameter("state", "state");
        request.setParameter("nonce", "nonce");
        request.setParameter("code", "abc123");

        // handle called with request, which should use session
        controller.handle(request);
    }

    @Test
    public void shouldAllowOrganizationParameter() {
        AuthenticationController controller = AuthenticationController.newBuilder("DOMAIN", "CLIENT_ID", "SECRET")
                .withOrganization("orgId_abc123")
                .build();

        String authUrl = controller.buildAuthorizeUrl(new MockHttpServletRequest(), new MockHttpServletResponse(), "https://me.com/redirect")
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

        String authUrl = controller.buildAuthorizeUrl(new MockHttpServletRequest(), new MockHttpServletResponse(), "https://me.com/redirect")
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
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withCookiePath("/Path")
                .build();

        controller.buildAuthorizeUrl(new MockHttpServletRequest(), response, "https://redirect.uri/here")
                .withState("state")
                .build();

        List<String> headers = response.getHeaders("Set-Cookie");

        assertThat(headers.size(), is(1));
        assertThat(headers, everyItem(is("com.auth0.state=state; HttpOnly; Max-Age=600; Path=/Path; SameSite=Lax")));
    }
}
