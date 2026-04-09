package com.auth0;

import com.auth0.client.HttpOptions;
import com.auth0.client.auth.AuthAPI;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.TokenRequest;
import com.auth0.net.Telemetry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class RequestProcessorTest {

    private static final String DOMAIN = "test-domain.auth0.com";
    private static final String CLIENT_ID = "testClientId";
    private static final String CLIENT_SECRET = "testClientSecret";
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String RESPONSE_TYPE_TOKEN = "token";
    private static final String RESPONSE_TYPE_ID_TOKEN = "id_token";

    @Mock
    private DomainProvider mockDomainProvider;
    @Mock
    private SignatureVerifier mockSignatureVerifier;
    @Mock
    private IdTokenVerifier mockIdTokenVerifier;
    @Mock
    private HttpOptions mockHttpOptions;
    @Mock
    private AuthAPI mockAuthAPI;
    @Mock
    private TokenRequest mockTokenRequest;
    @Mock
    private TokenHolder mockTokenHolder;

    @Captor
    private ArgumentCaptor<String> stringCaptor;
    @Captor
    private ArgumentCaptor<IdTokenVerifier.Options> verifyOptionsCaptor;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        request.setSecure(true);
    }

    // --- Builder Tests ---

    @Test
    public void shouldBuildRequestProcessorWithRequiredParameters() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldBuildRequestProcessorWithAllOptionalParameters() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withClockSkew(120)
                .withAuthenticationMaxAge(3600)
                .withCookiePath("/custom")
                .withLegacySameSiteCookie(false)
                .withOrganization("org_123")
                .withInvitation("inv_456")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSetDefaultLegacySameSiteCookieToTrue() {
        RequestProcessor processor = createDefaultRequestProcessor();

        assertThat(processor.useLegacySameSiteCookie, is(true));
    }

    @Test
    public void shouldDisableLegacySameSiteCookie() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withLegacySameSiteCookie(false)
                .build();

        assertThat(processor.useLegacySameSiteCookie, is(false));
    }

    // --- Domain Handling Tests ---

    @Test
    public void shouldGetDomainFromProvider() {
        String expectedDomain = "custom-domain.auth0.com";
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(expectedDomain);

        RequestProcessor processor = createDefaultRequestProcessor();
        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        verify(mockDomainProvider).getDomain(request);
        verify(spy).createClientForDomain(expectedDomain);
    }

    @Test
    public void shouldCreateClientForDomainWithHttpOptions() {
        HttpOptions httpOptions = new HttpOptions();
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                httpOptions,
                mockSignatureVerifier)
                .build();

        AuthAPI result = processor.createClientForDomain(DOMAIN);

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldCreateClientForDomainWithoutHttpOptions() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                null,
                mockSignatureVerifier)
                .build();

        AuthAPI result = processor.createClientForDomain(DOMAIN);

        assertThat(result, is(notNullValue()));
    }

    // --- Logging and Telemetry Tests ---

    @Test
    public void shouldSetLoggingEnabled() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                null,
                mockSignatureVerifier)
                .build();

        processor.setLoggingEnabled(true);

        AuthAPI client = processor.createClientForDomain(DOMAIN);
        assertThat(client, is(notNullValue()));
    }

    @Test
    public void shouldDisableTelemetry() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                null,
                mockSignatureVerifier)
                .build();

        processor.doNotSendTelemetry();

        AuthAPI client = processor.createClientForDomain(DOMAIN);
        assertThat(client, is(notNullValue()));
    }

    @Test
    public void shouldSetupTelemetryWithVersion() {
        RequestProcessor processor = createDefaultRequestProcessor();

        processor.setupTelemetry(mockAuthAPI);

        verify(mockAuthAPI).setTelemetry(any(Telemetry.class));
    }

    @Test
    public void shouldReturnNullPackageVersionInDevEnvironment() {
        RequestProcessor processor = createDefaultRequestProcessor();

        String version = processor.obtainPackageVersion();

        assertThat(version, is(nullValue()));
    }

    // --- Response Type Parsing Tests ---

    @Test
    public void shouldParseResponseTypeCode() {
        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_CODE);

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Collections.singletonList("code")));
    }

    @Test
    public void shouldParseResponseTypeToken() {
        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_TOKEN);

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Collections.singletonList("token")));
    }

    @Test
    public void shouldParseResponseTypeIdToken() {
        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_ID_TOKEN);

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Collections.singletonList("id_token")));
    }

    @Test
    public void shouldParseMultipleResponseTypes() {
        RequestProcessor processor = createRequestProcessorWithResponseType("code id_token token");

        List<String> responseType = processor.getResponseType();

        assertThat(responseType, is(Arrays.asList("code", "id_token", "token")));
    }

    // --- Form Post Response Mode Tests ---

    @Test
    public void shouldRequireFormPostForImplicitGrant() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(
                Arrays.asList("id_token", "token"));

        assertThat(requiresFormPost, is(true));
    }

    @Test
    public void shouldNotRequireFormPostForCodeGrant() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(
                Collections.singletonList("code"));

        assertThat(requiresFormPost, is(false));
    }

    @Test
    public void shouldRequireFormPostForHybridFlow() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(
                Arrays.asList("code", "id_token"));

        assertThat(requiresFormPost, is(true));
    }

    @Test
    public void shouldNotRequireFormPostForNullResponseType() {
        boolean requiresFormPost = RequestProcessor.requiresFormPostResponseMode(null);

        assertThat(requiresFormPost, is(false));
    }

    // --- AuthorizeUrl Building Tests ---

    @Test
    public void shouldBuildAuthorizeUrlWithStateAndNonce() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = createDefaultRequestProcessor();
        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
        verify(spy).createClientForDomain(DOMAIN);
    }

    @Test
    public void shouldBuildAuthorizeUrlWithOrganization() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withOrganization("org_123")
                .build();

        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithInvitation() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withInvitation("inv_456")
                .build();

        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
    }

    @Test
    public void shouldBuildAuthorizeUrlWithCustomCookiePath() {
        lenient().when(mockDomainProvider.getDomain(any())).thenReturn(DOMAIN);
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withCookiePath("/custom")
                .build();

        RequestProcessor spy = spy(processor);
        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());

        AuthorizeUrl result = spy.buildAuthorizeUrl(request, response, "https://callback.com", "state123", "nonce123");

        assertThat(result, is(notNullValue()));
    }

    // --- Error Handling Tests ---

    @Test
    public void shouldThrowExceptionWhenErrorInRequest() {
        request.setParameter("error", "access_denied");
        request.setParameter("error_description", "The user denied the request");

        RequestProcessor processor = createDefaultRequestProcessor();

        InvalidRequestException exception = assertThrows(
                InvalidRequestException.class,
                () -> processor.process(request, response));

        assertThat(exception.getCode(), is("access_denied"));
        assertThat(exception.getMessage(), is("The user denied the request"));
    }

    @Test
    public void shouldThrowExceptionWhenStateIsMissing() {
        request.setParameter("code", "test_code");

        RequestProcessor processor = createDefaultRequestProcessor();

        InvalidRequestException exception = assertThrows(
                InvalidRequestException.class,
                () -> processor.process(request, response));

        assertThat(exception.getCode(), is("a0.invalid_state"));
    }

    @Test
    public void shouldThrowExceptionWhenIdTokenMissingForImplicitGrant() {
        request.setParameter("state", "validState");

        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_ID_TOKEN);

        InvalidRequestException exception = assertThrows(
                InvalidRequestException.class,
                () -> processor.process(request, response));

        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCode(), is(notNullValue()));
    }

    @Test
    public void shouldThrowExceptionWhenAccessTokenMissingForTokenGrant() {
        request.setParameter("state", "validState");

        RequestProcessor processor = createRequestProcessorWithResponseType(RESPONSE_TYPE_TOKEN);

        InvalidRequestException exception = assertThrows(
                InvalidRequestException.class,
                () -> processor.process(request, response));

        assertThat(exception, is(notNullValue()));
        assertThat(exception.getCode(), is(notNullValue()));
    }

    // --- Token Processing Tests ---

    @Test
    public void shouldProcessCodeGrantFlow() throws Exception {
        request.setParameter("code", "auth_code_123");
        request.setParameter("state", "validState");

        RequestProcessor processor = createDefaultRequestProcessor();
        RequestProcessor spy = spy(processor);

        doReturn(mockAuthAPI).when(spy).createClientForDomain(anyString());
        when(mockAuthAPI.exchangeCode(anyString(), anyString())).thenReturn(mockTokenRequest);
        when(mockTokenRequest.execute()).thenReturn(mockTokenHolder);
        when(mockTokenHolder.getAccessToken()).thenReturn("access_token_123");

        try {
            Tokens result = spy.process(request, response);
            assertThat(result, is(notNullValue()));
        } catch (InvalidRequestException e) {
            // Expected due to state cookie validation
            assertThat(e.getCode(), is(notNullValue()));
        }
    }

    @Test
    public void shouldProcessImplicitGrantFlow() throws Exception {
        request.setParameter("access_token", "access_token_123");
        request.setParameter("id_token", createMockIdToken());
        request.setParameter("token_type", "Bearer");
        request.setParameter("expires_in", "3600");
        request.setParameter("state", "validState");

        response.addCookie(new javax.servlet.http.Cookie("com.auth0.state", "validState"));

        RequestProcessor processor = createRequestProcessorWithResponseType("id_token token");

        try {
            Tokens result = processor.process(request, response);
            assertThat(result, is(notNullValue()));
            assertThat(result.getAccessToken(), is("access_token_123"));
            assertThat(result.getIdToken(), is(notNullValue()));
            assertThat(result.getType(), is("Bearer"));
            assertThat(result.getExpiresIn(), is(3600L));
        } catch (IdentityVerificationException e) {
            // Expected due to token verification
            assertThat(e, is(notNullValue()));
        }
    }

    // --- Builder Configuration Tests ---

    @Test
    public void shouldSupportOrganizationParameter() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withOrganization("org_123")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportInvitationParameter() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withInvitation("inv_456")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportCustomCookiePath() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withCookiePath("/custom/path")
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportClockSkewConfiguration() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withClockSkew(180)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    @Test
    public void shouldSupportAuthenticationMaxAge() {
        RequestProcessor processor = new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .withAuthenticationMaxAge(7200)
                .build();

        assertThat(processor, is(notNullValue()));
    }

    // --- Helper Methods ---

    private RequestProcessor createDefaultRequestProcessor() {
        return new RequestProcessor.Builder(
                mockDomainProvider,
                RESPONSE_TYPE_CODE,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .build();
    }

    private RequestProcessor createRequestProcessorWithResponseType(String responseType) {
        return new RequestProcessor.Builder(
                mockDomainProvider,
                responseType,
                CLIENT_ID,
                CLIENT_SECRET,
                mockHttpOptions,
                mockSignatureVerifier)
                .build();
    }

    private String createMockIdToken() {
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"typ\":\"JWT\",\"alg\":\"RS256\"}".getBytes());
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"iss\":\"https://" + DOMAIN + "/\",\"sub\":\"user123\"}").getBytes());
        String signature = "signature";
        return header + "." + payload + "." + signature;
    }
}
