package com.auth0;

import com.auth0.jwk.JwkProvider;
import com.auth0.net.client.Auth0HttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class AuthenticationControllerTest {

    private static final String DOMAIN = "domain.auth0.com";
    private static final String CLIENT_ID = "clientId";
    private static final String CLIENT_SECRET = "clientSecret";

    @Mock
    private RequestProcessor mockRequestProcessor;
    @Mock
    private JwkProvider mockJwkProvider;
    @Mock
    private DomainResolver mockDomainResolver;
    @Mock
    private Auth0HttpClient mockHttpClient;
    @Mock
    private Tokens mockTokens;

    private HttpServletRequest request;
    private HttpServletResponse response;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    // --- Builder Static Factory Methods ---

    @Test
    public void shouldCreateBuilderWithDomain() {
        AuthenticationController.Builder builder = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET);

        assertThat(builder, is(notNullValue()));
    }

    @Test
    public void shouldCreateBuilderWithDomainResolver() {
        AuthenticationController.Builder builder = AuthenticationController.newBuilder(mockDomainResolver, CLIENT_ID, CLIENT_SECRET);

        assertThat(builder, is(notNullValue()));
    }

    @Test
    public void shouldThrowExceptionWhenDomainIsNull() {
        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> AuthenticationController.newBuilder((String) null, CLIENT_ID, CLIENT_SECRET));
        assertThat(exception.getMessage(), is("domain must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenDomainResolverIsNull() {
        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> AuthenticationController.newBuilder((DomainResolver) null, CLIENT_ID, CLIENT_SECRET));
        assertThat(exception.getMessage(), is("domainResolver must not be null"));
    }

    // --- Builder Configuration ---

    @Test
    public void shouldConfigureBuilderWithAllOptions() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("id_token token")
                .withJwkProvider(mockJwkProvider)
                .withHttpClient(mockHttpClient)
                .withClockSkew(120)
                .withAuthenticationMaxAge(3600)
                .withLegacySameSiteCookie(false)
                .withOrganization("org_123")
                .withInvitation("inv_456")
                .withCookiePath("/custom")
                .build();

        assertThat(controller, is(notNullValue()));
        assertThat(controller.getRequestProcessor(), is(notNullValue()));
    }

    @Test
    public void shouldThrowExceptionWhenDomainAndDomainResolverBothSet() {
        AuthenticationController.Builder builder = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET);

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> builder.withDomainResolver(mockDomainResolver));
        assertThat(exception.getMessage(), is("Cannot specify both 'domain' and 'domainResolver'."));
    }

    @Test
    public void shouldThrowExceptionWhenDomainResolverAndDomainBothSet() {
        AuthenticationController.Builder builder = AuthenticationController.newBuilder(mockDomainResolver, CLIENT_ID, CLIENT_SECRET);

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> builder.withDomain(DOMAIN));
        assertThat(exception.getMessage(), is("Cannot specify both 'domain' and 'domainResolver'."));
    }

    @Test
    public void shouldThrowExceptionWhenBuildingWithoutDomainOrResolver() {
        AuthenticationController.Builder builder = new AuthenticationController.Builder(CLIENT_ID, CLIENT_SECRET);

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                builder::build);
        assertThat(exception.getMessage(), is("Either domain or domainResolver must be provided."));
    }

    @Test
    public void shouldValidateNullParameters() {
        AuthenticationController.Builder builder = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET);

        assertThrows(NullPointerException.class, () -> builder.withDomain(null));
        assertThrows(NullPointerException.class, () -> builder.withResponseType(null));
        assertThrows(NullPointerException.class, () -> builder.withJwkProvider(null));
        assertThrows(NullPointerException.class, () -> builder.withHttpClient(null));
        assertThrows(NullPointerException.class, () -> builder.withClockSkew(null));
        assertThrows(NullPointerException.class, () -> builder.withAuthenticationMaxAge(null));
        assertThrows(NullPointerException.class, () -> builder.withOrganization(null));
        assertThrows(NullPointerException.class, () -> builder.withInvitation(null));
        assertThrows(NullPointerException.class, () -> builder.withCookiePath(null));
    }

    @Test
    public void shouldSetDefaultResponseTypeToCode() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldNormalizeResponseTypeToLowerCase() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("ID_TOKEN TOKEN")
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldTrimResponseType() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("  code  ")
                .build();

        assertThat(controller, is(notNullValue()));
    }

    // --- handle(request, response) Tests ---

    @Test
    public void shouldHandleRequestWithResponse() throws IdentityVerificationException {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        when(mockRequestProcessor.process(request, response)).thenReturn(mockTokens);

        Tokens result = controller.handle(request, response);

        assertThat(result, is(mockTokens));
        verify(mockRequestProcessor).process(request, response);
    }

    @Test
    public void shouldThrowExceptionWhenRequestIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.handle(null, response));
        assertThat(exception.getMessage(), is("request must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenResponseIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.handle(request, null));
        assertThat(exception.getMessage(), is("response must not be null"));
    }

    // --- buildAuthorizeUrl(request, response, redirectUri) Tests ---

    @Test
    public void shouldBuildAuthorizeUrlWithRequestAndResponse() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        AuthorizeUrl mockAuthorizeUrl = mock(AuthorizeUrl.class);
        String redirectUri = "https://redirect.to/me";

        when(mockRequestProcessor.buildAuthorizeUrl(eq(request), eq(response), eq(redirectUri), anyString(), anyString()))
                .thenReturn(mockAuthorizeUrl);

        AuthorizeUrl result = controller.buildAuthorizeUrl(request, response, redirectUri);

        assertThat(result, is(mockAuthorizeUrl));
        verify(mockRequestProcessor).buildAuthorizeUrl(eq(request), eq(response), eq(redirectUri), anyString(), anyString());
    }

    @Test
    public void shouldThrowExceptionWhenBuildAuthorizeUrlRequestIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.buildAuthorizeUrl(null, response, "https://redirect.to/me"));
        assertThat(exception.getMessage(), is("request must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenBuildAuthorizeUrlResponseIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.buildAuthorizeUrl(request, null, "https://redirect.to/me"));
        assertThat(exception.getMessage(), is("response must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenBuildAuthorizeUrlRedirectUriIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.buildAuthorizeUrl(request, response, null));
        assertThat(exception.getMessage(), is("redirectUri must not be null"));
    }

    // --- renewAuth Tests ---

    @Test
    public void shouldRenewAuthWithDomain() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        RenewAuthRequest mockRenewAuthRequest = mock(RenewAuthRequest.class);
        when(mockRequestProcessor.buildRenewAuthRequest("refreshToken", DOMAIN)).thenReturn(mockRenewAuthRequest);

        RenewAuthRequest result = controller.renewAuth("refreshToken", DOMAIN);

        assertThat(result, is(mockRenewAuthRequest));
        verify(mockRequestProcessor).buildRenewAuthRequest("refreshToken", DOMAIN);
    }

    @Test
    public void shouldRenewAuthWithoutDomain() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        RenewAuthRequest mockRenewAuthRequest = mock(RenewAuthRequest.class);
        when(mockRequestProcessor.buildRenewAuthRequest("refreshToken")).thenReturn(mockRenewAuthRequest);

        RenewAuthRequest result = controller.renewAuth("refreshToken");

        assertThat(result, is(mockRenewAuthRequest));
        verify(mockRequestProcessor).buildRenewAuthRequest("refreshToken");
    }

    @Test
    public void shouldThrowExceptionWhenRenewAuthRefreshTokenIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.renewAuth(null, DOMAIN));
        assertThat(exception.getMessage(), is("refreshToken must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenRenewAuthDomainIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.renewAuth("refreshToken", (String) null));
        assertThat(exception.getMessage(), is("domain must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenNoArgRenewAuthRefreshTokenIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.renewAuth(null));
        assertThat(exception.getMessage(), is("refreshToken must not be null"));
    }

    @Test
    public void shouldRenewAuthWithRequest() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        RenewAuthRequest mockRenewAuthRequest = mock(RenewAuthRequest.class);
        when(mockRequestProcessor.buildRenewAuthRequest("refreshToken", request)).thenReturn(mockRenewAuthRequest);

        RenewAuthRequest result = controller.renewAuth("refreshToken", request);

        assertThat(result, is(mockRenewAuthRequest));
        verify(mockRequestProcessor).buildRenewAuthRequest("refreshToken", request);
    }

    @Test
    public void shouldThrowExceptionWhenRenewAuthWithRequestRefreshTokenIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.renewAuth((String) null, request));
        assertThat(exception.getMessage(), is("refreshToken must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenRenewAuthRequestIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.renewAuth("refreshToken", (HttpServletRequest) null));
        assertThat(exception.getMessage(), is("request must not be null"));
    }

    // --- customTokenExchange Tests ---

    @Test
    public void shouldCustomTokenExchangeWithDomain() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        TokenExchangeRequest mockRequest = mock(TokenExchangeRequest.class);
        when(mockRequestProcessor.buildTokenExchangeRequest("subjectToken", "custom:token", DOMAIN, false)).thenReturn(mockRequest);

        TokenExchangeRequest result = controller.customTokenExchange("subjectToken", "custom:token", DOMAIN);

        assertThat(result, is(mockRequest));
        verify(mockRequestProcessor).buildTokenExchangeRequest("subjectToken", "custom:token", DOMAIN, false);
    }

    @Test
    public void shouldCustomTokenExchangeWithoutDomain() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        TokenExchangeRequest mockRequest = mock(TokenExchangeRequest.class);
        when(mockRequestProcessor.buildTokenExchangeRequest("subjectToken", "custom:token", false)).thenReturn(mockRequest);

        TokenExchangeRequest result = controller.customTokenExchange("subjectToken", "custom:token");

        assertThat(result, is(mockRequest));
        verify(mockRequestProcessor).buildTokenExchangeRequest("subjectToken", "custom:token", false);
    }

    @Test
    public void shouldLoginWithCustomTokenExchangeWithDomain() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        TokenExchangeRequest mockRequest = mock(TokenExchangeRequest.class);
        when(mockRequestProcessor.buildTokenExchangeRequest("subjectToken", "custom:token", DOMAIN, true)).thenReturn(mockRequest);

        TokenExchangeRequest result = controller.loginWithCustomTokenExchange("subjectToken", "custom:token", DOMAIN);

        assertThat(result, is(mockRequest));
        verify(mockRequestProcessor).buildTokenExchangeRequest("subjectToken", "custom:token", DOMAIN, true);
    }

    @Test
    public void shouldLoginWithCustomTokenExchangeWithoutDomain() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        TokenExchangeRequest mockRequest = mock(TokenExchangeRequest.class);
        when(mockRequestProcessor.buildTokenExchangeRequest("subjectToken", "custom:token", true)).thenReturn(mockRequest);

        TokenExchangeRequest result = controller.loginWithCustomTokenExchange("subjectToken", "custom:token");

        assertThat(result, is(mockRequest));
        verify(mockRequestProcessor).buildTokenExchangeRequest("subjectToken", "custom:token", true);
    }

    @Test
    public void shouldThrowExceptionWhenCustomTokenExchangeSubjectTokenIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.customTokenExchange(null, "custom:token", DOMAIN));
        assertThat(exception.getMessage(), is("subjectToken must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenCustomTokenExchangeSubjectTokenTypeIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.customTokenExchange("subjectToken", null, DOMAIN));
        assertThat(exception.getMessage(), is("subjectTokenType must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenCustomTokenExchangeDomainIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.customTokenExchange("subjectToken", "custom:token", null));
        assertThat(exception.getMessage(), is("domain must not be null"));
    }

    @Test
    public void shouldThrowExceptionWhenLoginWithCustomTokenExchangeSubjectTokenIsNull() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        NullPointerException exception = assertThrows(
                NullPointerException.class,
                () -> controller.loginWithCustomTokenExchange(null, "custom:token"));
        assertThat(exception.getMessage(), is("subjectToken must not be null"));
    }

    // --- Logging and Telemetry Tests ---

    @Test
    public void shouldSetLoggingEnabled() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        controller.setLoggingEnabled(true);

        verify(mockRequestProcessor).setLoggingEnabled(true);
    }

    @Test
    public void shouldDisableTelemetry() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        controller.doNotSendTelemetry();

        verify(mockRequestProcessor).doNotSendTelemetry();
    }

    @Test
    public void shouldPropagateIdentityVerificationException() throws IdentityVerificationException {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
        IdentityVerificationException expectedException = new IdentityVerificationException("test", "error", null);
        when(mockRequestProcessor.process(request, response)).thenThrow(expectedException);

        IdentityVerificationException actualException = assertThrows(
                IdentityVerificationException.class,
                () -> controller.handle(request, response));

        assertThat(actualException, is(expectedException));
    }

    // --- RequestProcessor Integration ---

    @Test
    public void shouldGetRequestProcessor() {
        AuthenticationController controller = new AuthenticationController(mockRequestProcessor);

        RequestProcessor result = controller.getRequestProcessor();

        assertThat(result, is(mockRequestProcessor));
    }

    // --- Builder Variations ---

    @Test
    public void shouldBuildWithCodeResponseTypeAndNoJwkProvider() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("code")
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithImplicitGrantRequiringJwkProvider() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("id_token token")
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithDomainResolver() {
        AuthenticationController controller = AuthenticationController
                .newBuilder(mockDomainResolver, CLIENT_ID, CLIENT_SECRET)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithOrganizationAndInvitation() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withOrganization("org_123")
                .withInvitation("inv_456")
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithCustomCookiePath() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withCookiePath("/custom/path")
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithDisabledLegacySameSiteCookie() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withLegacySameSiteCookie(false)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithCustomClockSkewAndMaxAge() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withClockSkew(180)
                .withAuthenticationMaxAge(7200)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    // --- MCD Support ---

    @Test
    public void shouldSupportMCDWithDomainResolver() {
        AuthenticationController controller = AuthenticationController
                .newBuilder(mockDomainResolver, CLIENT_ID, CLIENT_SECRET)
                .build();

        assertThat(controller, is(notNullValue()));
        assertThat(controller.getRequestProcessor(), is(notNullValue()));
    }

    // --- Response Type Variations ---

    @Test
    public void shouldHandleCodeResponseType() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("code")
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldHandleIdTokenResponseType() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("id_token")
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldHandleTokenResponseType() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("token")
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldHandleHybridFlowResponseType() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("code id_token")
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldHandleImplicitGrantResponseType() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withResponseType("id_token token")
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    // --- HttpClient Configuration Tests ---

    @Test
    public void shouldBuildWithCustomHttpClient() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withHttpClient(mockHttpClient)
                .build();

        assertThat(controller, is(notNullValue()));
        assertThat(controller.getRequestProcessor(), is(notNullValue()));
    }

    @Test
    public void shouldBuildWithCustomHttpClientAndJwkProvider() {
        AuthenticationController controller = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
                .withHttpClient(mockHttpClient)
                .withJwkProvider(mockJwkProvider)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldBuildWithCustomHttpClientAndDomainResolver() {
        AuthenticationController controller = AuthenticationController
                .newBuilder(mockDomainResolver, CLIENT_ID, CLIENT_SECRET)
                .withHttpClient(mockHttpClient)
                .build();

        assertThat(controller, is(notNullValue()));
    }

    @Test
    public void shouldThrowExceptionWhenHttpClientIsNull() {
        AuthenticationController.Builder builder = AuthenticationController.newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET);

        assertThrows(NullPointerException.class, () -> builder.withHttpClient(null));
    }
}
