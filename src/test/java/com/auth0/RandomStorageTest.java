package com.auth0;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

public class RandomStorageTest {

    @Mock
    private HttpServletRequest request; // Mockito mock for HttpServletRequest
    @Mock
    private HttpSession session;     // Mockito mock for HttpSession

    // A map to simulate the session attributes for our mocked HttpSession
    private Map<String, Object> sessionAttributes;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        sessionAttributes = new HashMap<>();

        when(request.getSession()).thenReturn(session);
        when(request.getSession(anyBoolean())).thenReturn(session);

        doAnswer(invocation -> {
            String name = invocation.getArgument(0);
            Object value = invocation.getArgument(1);
            sessionAttributes.put(name, value);
            return null;
        }).when(session).setAttribute(anyString(), any());

        when(session.getAttribute(anyString())).thenAnswer(invocation -> {
            String name = invocation.getArgument(0);
            return sessionAttributes.get(name);
        });

        doAnswer(invocation -> {
            String name = invocation.getArgument(0);
            sessionAttributes.remove(name);
            return null;
        }).when(session).removeAttribute(anyString());
    }

    @Test
    public void shouldSetState() {

        RandomStorage.setSessionState(request, "123456");
        assertThat(request.getSession().getAttribute("com.auth0.state"), is("123456"));
    }

    @Test
    public void shouldAcceptBothNullStates() {
        boolean validState = RandomStorage.checkSessionState(request, null);
        assertThat(validState, is(true));
    }

    @Test
    public void shouldFailIfSessionStateIsNullButCurrentStateNotNull() {
        boolean validState = RandomStorage.checkSessionState(request, "12345");
        assertThat(validState, is(false));
    }

    @Test
    public void shouldCheckAndRemoveInvalidState() {
        request.getSession().setAttribute("com.auth0.state", "123456");

        boolean validState = RandomStorage.checkSessionState(request, "abcdef");
        assertThat(validState, is(false));
        assertThat(request.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldCheckAndRemoveCorrectState() {
        sessionAttributes.put("com.auth0.state", "123456");

        boolean validState = RandomStorage.checkSessionState(request, "123456");
        assertThat(validState, is(true));
        assertThat(request.getSession().getAttribute("com.auth0.state"), is(nullValue()));
    }

    @Test
    public void shouldSetNonce() {
        RandomStorage.setSessionNonce(request, "123456");
        assertThat(request.getSession().getAttribute("com.auth0.nonce"), is("123456"));
    }

    @Test
    public void shouldGetAndRemoveNonce() {
        request.getSession().setAttribute("com.auth0.nonce", "123456");

        String nonce = RandomStorage.removeSessionNonce(request);
        assertThat(nonce, is("123456"));
        assertThat(request.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }

    @Test
    public void shouldGetAndRemoveNonceIfMissing() {
        String nonce = RandomStorage.removeSessionNonce(request);
        assertThat(nonce, is(nullValue()));
        assertThat(request.getSession().getAttribute("com.auth0.nonce"), is(nullValue()));
    }
}
