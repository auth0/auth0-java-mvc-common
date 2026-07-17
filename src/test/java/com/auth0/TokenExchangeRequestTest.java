package com.auth0;

import com.auth0.exception.Auth0Exception;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class TokenExchangeRequestTest {

    private static final String DOMAIN = "test-domain.auth0.com";
    private static final String ISSUER = "https://test-domain.auth0.com/";
    private static final String SUBJECT_TOKEN = "ext-token";
    private static final String SUBJECT_TOKEN_TYPE = "custom:legacy-token";

    @Mock
    private RequestProcessor mockProcessor;
    @Mock
    private Tokens mockTokens;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    private TokenExchangeRequest newRequest(String subjectToken, String subjectTokenType, boolean loginSemantics) {
        return new TokenExchangeRequest(mockProcessor, subjectToken, subjectTokenType, DOMAIN, ISSUER, loginSemantics, null);
    }

    @Test
    public void shouldDelegateToProcessorWithConfiguredParameters() throws Exception {
        when(mockProcessor.executeCustomTokenExchange(
                eq(SUBJECT_TOKEN), eq(SUBJECT_TOKEN_TYPE), eq("api"), eq("read:foo"), eq("org_1"),
                eq(DOMAIN), eq(ISSUER), eq(false))).thenReturn(mockTokens);

        Tokens result = newRequest(SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, false)
                .withAudience("api")
                .withScope("read:foo")
                .withOrganization("org_1")
                .execute();

        assertSame(mockTokens, result);
        verify(mockProcessor).executeCustomTokenExchange(
                SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, "api", "read:foo", "org_1", DOMAIN, ISSUER, false);
    }

    @Test
    public void shouldPassNullOptionalParametersWhenNotSet() throws Exception {
        when(mockProcessor.executeCustomTokenExchange(
                any(), any(), isNull(), isNull(), isNull(), any(), any(), eq(true))).thenReturn(mockTokens);

        newRequest(SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, true).execute();

        verify(mockProcessor).executeCustomTokenExchange(
                SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, null, null, null, DOMAIN, ISSUER, true);
    }

    @Test
    public void shouldUseClientLevelOrganizationDefault() throws Exception {
        TokenExchangeRequest request = new TokenExchangeRequest(
                mockProcessor, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, DOMAIN, ISSUER, true, "org_default");
        when(mockProcessor.executeCustomTokenExchange(
                any(), any(), any(), any(), eq("org_default"), any(), any(), anyBoolean())).thenReturn(mockTokens);

        request.execute();

        verify(mockProcessor).executeCustomTokenExchange(
                SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, null, null, "org_default", DOMAIN, ISSUER, true);
    }

    @Test
    public void shouldOverrideClientLevelOrganization() throws Exception {
        TokenExchangeRequest request = new TokenExchangeRequest(
                mockProcessor, SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, DOMAIN, ISSUER, true, "org_default");
        when(mockProcessor.executeCustomTokenExchange(
                any(), any(), any(), any(), eq("org_override"), any(), any(), anyBoolean())).thenReturn(mockTokens);

        request.withOrganization("org_override").execute();

        verify(mockProcessor).executeCustomTokenExchange(
                SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, null, null, "org_override", DOMAIN, ISSUER, true);
    }

    @Test
    public void shouldThrowOnEmptySubjectToken() {
        CustomTokenExchangeException exception = assertThrows(
                CustomTokenExchangeException.class,
                () -> newRequest("   ", SUBJECT_TOKEN_TYPE, false).execute());
        assertThat(exception.isInvalidTokenFormat(), is(true));
    }

    @Test
    public void shouldThrowOnBearerPrefixedSubjectToken() {
        CustomTokenExchangeException exception = assertThrows(
                CustomTokenExchangeException.class,
                () -> newRequest("Bearer ext-token", SUBJECT_TOKEN_TYPE, false).execute());
        assertThat(exception.isInvalidTokenFormat(), is(true));
    }

    @Test
    public void shouldThrowOnSubjectTokenWithSurroundingWhitespace() {
        CustomTokenExchangeException exception = assertThrows(
                CustomTokenExchangeException.class,
                () -> newRequest(" ext-token\n", SUBJECT_TOKEN_TYPE, false).execute());
        assertThat(exception.isInvalidTokenFormat(), is(true));
    }

    @Test
    public void shouldThrowOnSubjectTokenWithLeadingSpaceBeforeBearerPrefix() {
        CustomTokenExchangeException exception = assertThrows(
                CustomTokenExchangeException.class,
                () -> newRequest(" Bearer ext-token", SUBJECT_TOKEN_TYPE, false).execute());
        assertThat(exception.isInvalidTokenFormat(), is(true));
    }

    @Test
    public void shouldThrowOnNonUriSubjectTokenType() {
        CustomTokenExchangeException exception = assertThrows(
                CustomTokenExchangeException.class,
                () -> newRequest(SUBJECT_TOKEN, "not a uri", false).execute());
        assertThat(exception.isInvalidTokenTypeUri(), is(true));
    }

    @Test
    public void shouldThrowOnRelativeUriSubjectTokenType() {
        CustomTokenExchangeException exception = assertThrows(
                CustomTokenExchangeException.class,
                () -> newRequest(SUBJECT_TOKEN, "legacy-token", false).execute());
        assertThat(exception.isInvalidTokenTypeUri(), is(true));
    }

    @Test
    public void shouldAcceptCustomSchemeSubjectTokenType() throws Exception {
        when(mockProcessor.executeCustomTokenExchange(any(), any(), any(), any(), any(), any(), any(), anyBoolean()))
                .thenReturn(mockTokens);

        newRequest(SUBJECT_TOKEN, "urn:partner:session", false).execute();

        verify(mockProcessor).executeCustomTokenExchange(
                SUBJECT_TOKEN, "urn:partner:session", null, null, null, DOMAIN, ISSUER, false);
    }

    @Test
    public void shouldNotValidateBeforeReservedNamespaceSubjectTokenType() throws Exception {
        // Reserved urn:ietf:* namespaces are accepted client-side; the server enforces rejection.
        when(mockProcessor.executeCustomTokenExchange(any(), any(), any(), any(), any(), any(), any(), anyBoolean()))
                .thenReturn(mockTokens);

        newRequest(SUBJECT_TOKEN, "urn:ietf:params:oauth:token-type:id_token", false).execute();

        verify(mockProcessor).executeCustomTokenExchange(
                SUBJECT_TOKEN, "urn:ietf:params:oauth:token-type:id_token", null, null, null, DOMAIN, ISSUER, false);
    }

    @Test
    public void shouldPropagateAuth0Exception() throws Exception {
        when(mockProcessor.executeCustomTokenExchange(any(), any(), any(), any(), any(), any(), any(), anyBoolean()))
                .thenThrow(new Auth0Exception("boom"));

        assertThrows(Auth0Exception.class,
                () -> newRequest(SUBJECT_TOKEN, SUBJECT_TOKEN_TYPE, false).execute());
    }
}
