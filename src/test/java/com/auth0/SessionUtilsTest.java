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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

public class SessionUtilsTest {

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpSession session;

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
    public void shouldGetAndRemoveAttribute() {
        sessionAttributes.put("name", "value");

        assertThat(SessionUtils.remove(request, "name"), is("value"));
        assertThat(sessionAttributes.get("name"), is(nullValue()));
    }

    @Test
    public void shouldGetAttribute() {
        sessionAttributes.put("name", "value");

        assertThat(SessionUtils.get(request, "name"), is("value"));
        assertThat(sessionAttributes.get("name"), is("value"));
    }

    @Test
    public void shouldGetNullAttributeIfMissing() {
        assertThat(SessionUtils.get(request, "name"), is(nullValue()));
        assertThat(sessionAttributes.get("name"), is(nullValue()));
    }

    @Test
    public void shouldSetAttribute() {
        SessionUtils.set(request, "name", "value");
        assertThat(sessionAttributes.get("name"), is("value"));
    }

}
