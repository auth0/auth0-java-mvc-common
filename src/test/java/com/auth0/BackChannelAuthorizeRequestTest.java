package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.BackChannelAuthorizeResponse;
import com.auth0.net.Request;
import com.auth0.net.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class BackChannelAuthorizeRequestTest {

    private static final String DOMAIN = "domain.auth0.com";
    private static final String ISSUER = "https://domain.auth0.com/";
    private static final String SCOPE = "openid profile";
    private static final String BINDING_MESSAGE = "Approve login 1234";
    private static final Map<String, Object> LOGIN_HINT =
            Collections.singletonMap("format", "iss_sub");

    @Mock
    private AuthAPI mockClient;
    @Mock
    private Request<BackChannelAuthorizeResponse> mockRequest;
    @Mock
    private Response<BackChannelAuthorizeResponse> mockResponse;
    @Mock
    private BackChannelAuthorizeResponse mockBody;

    @BeforeEach
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        when(mockRequest.execute()).thenReturn(mockResponse);
        when(mockResponse.getBody()).thenReturn(mockBody);
    }

    private BackChannelAuthorizeRequest newRequest() {
        return new BackChannelAuthorizeRequest(mockClient, SCOPE, BINDING_MESSAGE, LOGIN_HINT, DOMAIN, ISSUER);
    }

    @Test
    public void shouldUseThreeArgOverloadWhenNoOptionalsSet() throws Exception {
        when(mockClient.authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT)).thenReturn(mockRequest);

        BackChannelAuthorizeResponse result = newRequest().execute();

        assertSame(mockBody, result);
        verify(mockClient).authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT);
        verify(mockClient, never()).authorizeBackChannel(
                eq(SCOPE), eq(BINDING_MESSAGE), eq(LOGIN_HINT),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyInt());
    }

    @Test
    public void shouldUseFiveArgOverloadWhenAudienceSet() throws Exception {
        when(mockClient.authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT, "api", null))
                .thenReturn(mockRequest);

        newRequest().withAudience("api").execute();

        verify(mockClient).authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT, "api", null);
    }

    @Test
    public void shouldUseFiveArgOverloadWhenRequestedExpirySet() throws Exception {
        when(mockClient.authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT, null, 300))
                .thenReturn(mockRequest);

        newRequest().withRequestedExpiry(300).execute();

        verify(mockClient).authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT, null, 300);
    }

    @Test
    public void shouldPassBothOptionalsWhenSet() throws Exception {
        when(mockClient.authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT, "api", 120))
                .thenReturn(mockRequest);

        newRequest().withAudience("api").withRequestedExpiry(120).execute();

        verify(mockClient).authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT, "api", 120);
    }

    @Test
    public void shouldReturnResponseBody() throws Exception {
        when(mockClient.authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT)).thenReturn(mockRequest);
        when(mockBody.getAuthReqId()).thenReturn("auth-req-123");
        when(mockBody.getInterval()).thenReturn(5);
        when(mockBody.getExpiresIn()).thenReturn(600L);

        BackChannelAuthorizeResponse result = newRequest().execute();

        assertThat(result.getAuthReqId(), is("auth-req-123"));
        assertThat(result.getInterval(), is(5));
        assertThat(result.getExpiresIn(), is(600L));
    }

    @Test
    public void shouldPropagateAuth0Exception() throws Exception {
        when(mockClient.authorizeBackChannel(SCOPE, BINDING_MESSAGE, LOGIN_HINT)).thenReturn(mockRequest);
        when(mockRequest.execute()).thenThrow(new Auth0Exception("boom"));

        assertThrows(Auth0Exception.class, () -> newRequest().execute());
    }
}
