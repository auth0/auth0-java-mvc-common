package com.auth0;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class SessionUtilsTest {
    @Test
    public void shouldGetAndRemoveAttribute() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("name", "value");

        assertThat(SessionUtils.remove(req, "name"), is("value"));
        assertThat(req.getSession().getAttribute("name"), is(nullValue()));
    }

    @Test
    public void shouldGetAttribute() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("name", "value");

        assertThat(SessionUtils.get(req, "name"), is("value"));
        assertThat(req.getSession().getAttribute("name"), is("value"));
    }

    @Test
    public void shouldGetNullAttributeIfMissing() {
        MockHttpServletRequest req = new MockHttpServletRequest();

        assertThat(SessionUtils.get(req, "name"), is(nullValue()));
        assertThat(req.getSession().getAttribute("name"), is(nullValue()));
    }

    @Test
    public void shouldSetAttribute() {
        MockHttpServletRequest req = new MockHttpServletRequest();

        SessionUtils.set(req, "name", "value");
        assertThat(req.getSession().getAttribute("name"), is("value"));
    }

}
