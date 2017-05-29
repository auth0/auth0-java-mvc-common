package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.jwk.JwkProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class AuthenticationControllerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    @Mock
    private RequestProcessor requestProcessor;
    @Mock
    private RequestProcessorFactory requestProcessorFactory;
    @Mock
    private AuthAPI client;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(requestProcessorFactory.forCodeGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString())).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString())).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString(), any(JwkProvider.class))).thenReturn(requestProcessor);
        when(requestProcessor.getClient()).thenReturn(client);
    }

    @Test
    public void shouldThrowOnMissingDomain() throws Exception {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder(null, "clientId", "clientSecret");
    }

    @Test
    public void shouldThrowOnMissingClientId() throws Exception {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", null, "clientSecret");
    }

    @Test
    public void shouldThrowOnMissingClientSecret() throws Exception {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", "clientId", null);
    }

    @Test
    public void shouldThrowOnMissingJwkProvider() throws Exception {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withJwkProvider(null);
    }

    @Test
    public void shouldThrowOnMissingResponseType() throws Exception {
        exception.expect(NullPointerException.class);

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType(null);
    }

    @Test
    public void shouldThrowOnInvalidResponseType() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Response Type must contain any combination of 'code', 'token' or 'id_token'.");

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("responseType")
                .build();
    }

    @Test
    public void shouldCreateWithDefaultValues() throws Exception {
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .build();
    }

    @Test
    public void shouldAcceptAnyValidResponseType() throws Exception {
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("code")
                .build();
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .build();
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token")
                .build();
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token code")
                .build();
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token id_token code")
                .build();
    }

    @Test
    public void shouldThrowOnNotSupportedResponseType() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Response Type 'token id_token' is not supported yet.");

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token id_token")
                .build();
    }

    @Test
    public void shouldCreateWithJwkProvider() throws Exception {
        JwkProvider provider = mock(JwkProvider.class);
        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withJwkProvider(provider)
                .build();
    }

    @Test
    public void shouldProcessRequestWithCodeGrantByDefault() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant("domain", "clientId", "clientSecret", "code")).thenReturn(requestProcessor);

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        controller.handle(req);

        verify(requestProcessorFactory).forCodeGrant("domain", "clientId", "clientSecret", "code");
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldProcessRequestWithCodeGrant() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant("domain", "clientId", "clientSecret", "code")).thenReturn(requestProcessor);

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("code")
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        controller.handle(req);

        verify(requestProcessorFactory).forCodeGrant("domain", "clientId", "clientSecret", "code");
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldProcessRequestWithImplicitGrantRS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        JwkProvider jwtProvider = mock(JwkProvider.class);
        when(requestProcessorFactory.forImplicitGrant("domain", "clientId", "clientSecret", "token", jwtProvider)).thenReturn(requestProcessor);

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token")
                .withJwkProvider(jwtProvider)
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        controller.handle(req);

        verify(requestProcessorFactory).forImplicitGrant("domain", "clientId", "clientSecret", "token", jwtProvider);
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldProcessRequestWithImplicitGrantHS() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrant("domain", "clientId", "clientSecret", "token")).thenReturn(requestProcessor);

        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token")
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        controller.handle(req);

        verify(requestProcessorFactory).forImplicitGrant("domain", "clientId", "clientSecret", "token");
        verify(requestProcessor).process(req);
    }

    @Test
    public void shouldThrowIfSecretCanNotBeParsedWithImplicitGrantHS() throws Exception {
        exception.expect(UnsupportedOperationException.class);

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrant("domain", "clientId", "clientSecret", "token")).thenThrow(UnsupportedEncodingException.class);

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token")
                .build(requestProcessorFactory);
    }

    @Test
    public void shouldBuildAuthorizeUriWithRandomStateAndNonce() throws Exception {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        when(requestProcessor.getResponseType()).thenReturn(Arrays.asList("token", "id_token"));
        controller.buildAuthorizeUrl(req, "https://redirect.uri/here");

        verify(requestProcessor).buildAuthorizeUrl(eq(req), eq("https://redirect.uri/here"), anyString(), anyString());
    }

    @Test
    public void shouldEnableLogging() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant("domain", "clientId", "clientSecret", "code")).thenReturn(requestProcessor);
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .build(requestProcessorFactory);

        controller.setLoggingEnabled(true);
        verify(client).setLoggingEnabled(true);
    }

    @Test
    public void shouldDisableLogging() throws Exception {
        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forCodeGrant("domain", "clientId", "clientSecret", "code")).thenReturn(requestProcessor);
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .build(requestProcessorFactory);

        controller.setLoggingEnabled(false);
        verify(client).setLoggingEnabled(false);
    }

}