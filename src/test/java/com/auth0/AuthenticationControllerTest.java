package com.auth0;

import com.auth0.jwk.JwkProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.text.IsEmptyString.emptyOrNullString;
import static org.junit.Assert.assertThat;
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

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(requestProcessorFactory.forCodeGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString())).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString())).thenReturn(requestProcessor);
        when(requestProcessorFactory.forImplicitGrant(eq("domain"), eq("clientId"), eq("clientSecret"), anyString(), any(JwkProvider.class))).thenReturn(requestProcessor);
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
        exception.expect(UnsupportedEncodingException.class);

        RequestProcessorFactory requestProcessorFactory = mock(RequestProcessorFactory.class);
        when(requestProcessorFactory.forImplicitGrant("domain", "clientId", "clientSecret", "token")).thenThrow(UnsupportedEncodingException.class);

        AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token")
                .build(requestProcessorFactory);
    }

    @Test
    public void shouldBuildAuthorizeUriWithCustomStateAndNonce() throws Exception {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        when(requestProcessor.getResponseType()).thenReturn(Arrays.asList("token", "id_token"));
        controller.buildAuthorizeUrl(req, "https://redirect.uri/here", "state", "nonce");

        verify(requestProcessor).buildAuthorizeUrl("https://redirect.uri/here", "state", "nonce");
    }

    @Test
    public void shouldNotSaveNonceInSessionIfRequestTypeIsNotIdToken() throws Exception {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("token")
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        when(requestProcessor.getResponseType()).thenReturn(Collections.singletonList("token"));
        controller.buildAuthorizeUrl(req, "https://redirect.uri/here");

        ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        verify(requestProcessor).buildAuthorizeUrl(eq("https://redirect.uri/here"), stateCaptor.capture(), nonceCaptor.capture());

        assertThat(stateCaptor.getValue(), is(not(emptyOrNullString())));
        assertThat(nonceCaptor.getValue(), is(not(emptyOrNullString())));
        String savedState = (String) req.getSession(true).getAttribute("com.auth0.state");
        String savedNonce = (String) req.getSession(true).getAttribute("com.auth0.nonce");
        assertThat(savedState, is(stateCaptor.getValue()));
        assertThat(savedNonce, is(nullValue()));
    }

    @Test
    public void shouldSaveNonceInSessionIfRequestTypeIsIdToken() throws Exception {
        AuthenticationController controller = AuthenticationController.newBuilder("domain", "clientId", "clientSecret")
                .withResponseType("id_token")
                .build(requestProcessorFactory);

        HttpServletRequest req = new MockHttpServletRequest();
        when(requestProcessor.getResponseType()).thenReturn(Arrays.asList("token", "id_token"));
        controller.buildAuthorizeUrl(req, "https://redirect.uri/here");

        ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nonceCaptor = ArgumentCaptor.forClass(String.class);
        verify(requestProcessor).buildAuthorizeUrl(eq("https://redirect.uri/here"), stateCaptor.capture(), nonceCaptor.capture());

        assertThat(stateCaptor.getValue(), is(not(emptyOrNullString())));
        assertThat(nonceCaptor.getValue(), is(not(emptyOrNullString())));
        String savedState = (String) req.getSession(true).getAttribute("com.auth0.state");
        String savedNonce = (String) req.getSession(true).getAttribute("com.auth0.nonce");
        assertThat(savedState, is(stateCaptor.getValue()));
        assertThat(savedNonce, is(nonceCaptor.getValue()));
    }

}