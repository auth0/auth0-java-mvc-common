package com.auth0;

import com.auth0.exception.Auth0Exception;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class BackChannelTokenRequestTest {

    private static final String DOMAIN = "domain.auth0.com";
    private static final String ISSUER = "https://domain.auth0.com/";
    private static final String AUTH_REQ_ID = "auth-req-123";

    @Mock
    private RequestProcessor mockProcessor;
    @Mock
    private Tokens mockTokens;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    private BackChannelTokenRequest newRequest() {
        return new BackChannelTokenRequest(mockProcessor, AUTH_REQ_ID, DOMAIN, ISSUER);
    }

    @Test
    public void shouldDelegateToProcessor() throws Exception {
        when(mockProcessor.executeBackChannelPoll(AUTH_REQ_ID, DOMAIN, ISSUER)).thenReturn(mockTokens);

        Tokens result = newRequest().execute();

        assertSame(mockTokens, result);
        verify(mockProcessor).executeBackChannelPoll(AUTH_REQ_ID, DOMAIN, ISSUER);
    }

    @Test
    public void shouldPropagatePendingException() throws Exception {
        BackChannelAuthorizationException pending = new BackChannelAuthorizationException(
                BackChannelAuthorizationException.AUTHORIZATION_PENDING, "pending");
        when(mockProcessor.executeBackChannelPoll(AUTH_REQ_ID, DOMAIN, ISSUER)).thenThrow(pending);

        BackChannelAuthorizationException thrown = assertThrows(
                BackChannelAuthorizationException.class, () -> newRequest().execute());
        org.hamcrest.MatcherAssert.assertThat(thrown.isAuthorizationPending(), org.hamcrest.core.Is.is(true));
    }

    @Test
    public void shouldPropagateAuth0Exception() throws Exception {
        when(mockProcessor.executeBackChannelPoll(AUTH_REQ_ID, DOMAIN, ISSUER))
                .thenThrow(new Auth0Exception("boom"));

        assertThrows(Auth0Exception.class, () -> newRequest().execute());
    }
}
