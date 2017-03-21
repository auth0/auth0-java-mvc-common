package com.auth0;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class SessionUtilsTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldGetAndRemoveAttribute() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("name", "value");

        assertThat((String) SessionUtils.remove(req, "name"), is("value"));
        assertThat(req.getSession().getAttribute("name"), is(nullValue()));
    }

    @Test
    public void shouldGetAttribute() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute("name", "value");

        assertThat((String) SessionUtils.get(req, "name"), is("value"));
        assertThat((String) req.getSession().getAttribute("name"), is("value"));
    }

    @Test
    public void shouldGetNullAttributeIfMissing() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        assertThat(SessionUtils.get(req, "name"), is(nullValue()));
        assertThat(req.getSession().getAttribute("name"), is(nullValue()));
    }

    @Test
    public void shouldSetAttribute() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        SessionUtils.set(req, "name", "value");
        assertThat((String) req.getSession().getAttribute("name"), is("value"));
    }

}