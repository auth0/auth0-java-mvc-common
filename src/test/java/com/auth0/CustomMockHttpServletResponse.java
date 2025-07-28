package com.auth0;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

public class CustomMockHttpServletResponse extends HttpServletResponseWrapper {

    private final Map<String, List<String>> headers = new HashMap<>();
    private final StringWriter writer = new StringWriter();


    public CustomMockHttpServletResponse(HttpServletResponse response) {
        super(response);
    }

    public Collection<String> getHeaders(String name) {
        return headers.getOrDefault(name, Collections.emptyList());
    }

    @Override
    public void addHeader(String name, String value) {
        headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    }

    @Override
    public void setHeader(String name, String value) {
        List<String> list = new ArrayList<>();
        list.add(value);
        headers.put(name, list);
    }

    @Override
    public void addCookie(Cookie cookie) {

        StringBuilder cookieString = new StringBuilder(cookie.getName())
                .append("=")
                .append(cookie.getValue() != null ? cookie.getValue() : "");

        cookieString.append("; Path=").append(cookie.getPath() != null ? cookie.getPath() : "/");

        if (cookie.getMaxAge() >= 0) { // Max-Age should be >= 0 for valid values
            cookieString.append("; Max-Age=").append(cookie.getMaxAge());
        }

        if (cookie.getSecure()) {
            cookieString.append("; Secure");
        }

        if (cookie.isHttpOnly()) {
            cookieString.append("; HttpOnly");
        }

        // SameSite: Your dummy AuthCookie.buildHeaderString() includes SameSite.
        // If this addCookie is used for other contexts, you might need to infer SameSite or pass it.
        // For now, based on your original problem, your store method bypasses this.
        // The `addCookie` method in your `CustomMockHttpServletResponse` should either not worry about SameSite
        // (if it's always added by `AuthCookie.buildHeaderString()`),
        // or it should have a simplified inference that matches your "removed" cookie strings.
        // Let's remove the `SameSite=None` hardcoding here. The `AuthCookie` generates it for `store`.
        // For `removeCookie`, the assertion does *not* expect SameSite on the removed cookies.

        addHeader("Set-Cookie", cookieString.toString());
    }

    @Override
    public Collection<String> getHeaderNames() {
        return headers.keySet();
    }

    static class BasicHttpServletResponse implements HttpServletResponse {
        private int status = 200;
        private final Map<String, List<String>> headers = new HashMap<>();

        @Override public void addCookie(Cookie cookie) { /* not implemented */ }
        @Override public boolean containsHeader(String name) { return headers.containsKey(name); }
        @Override public String encodeURL(String url) { return url; }
        @Override public String encodeRedirectURL(String url) { return url; }

        @Override
        public String encodeUrl(String s) {
            return "";
        }

        @Override
        public String encodeRedirectUrl(String s) {
            return "";
        }

        @Override public void sendError(int sc, String msg) throws IOException { /* not implemented */ }
        @Override public void sendError(int sc) throws IOException { /* not implemented */ }
        @Override public void sendRedirect(String location) throws IOException { /* not implemented */ }
        @Override public void setDateHeader(String name, long date) { /* not implemented */ }
        @Override public void addDateHeader(String name, long date) { /* not implemented */ }
        @Override public void setHeader(String name, String value) { headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value); } // Basic header setting
        @Override public void addHeader(String name, String value) { headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value); }
        @Override public void setIntHeader(String name, int value) { /* not implemented */ }
        @Override public void addIntHeader(String name, int value) { /* not implemented */ }
        @Override public void setStatus(int sc) { this.status = sc; }
        @Override public void setStatus(int sc, String sm) { this.status = sc; }
        @Override public int getStatus() { return status; }
        @Override public String getHeader(String name) { return headers.containsKey(name) ? headers.get(name).get(0) : null; } // Basic getHeader
        @Override public Collection<String> getHeaders(String name) { return headers.getOrDefault(name, Collections.emptyList()); }
        @Override public Collection<String> getHeaderNames() { return headers.keySet(); }
        @Override public String getContentType() { return null; }
        @Override public String getCharacterEncoding() { return null; }
        @Override public ServletOutputStream getOutputStream() throws IOException { return null; }
        @Override public PrintWriter getWriter() throws IOException { return null; }
        @Override public void setCharacterEncoding(String charset) { /* not implemented */ }
        @Override public void setContentLength(int len) { /* not implemented */ }
        @Override public void setContentLengthLong(long len) { /* not implemented */ }
        @Override public void setContentType(String type) { /* not implemented */ }
        @Override public void setBufferSize(int size) { /* not implemented */ }
        @Override public int getBufferSize() { return 0; }
        @Override public void flushBuffer() throws IOException { /* not implemented */ }
        @Override public void resetBuffer() { /* not implemented */ }
        @Override public boolean isCommitted() { return false; }
        @Override public void reset() { /* not implemented */ }
        @Override public void setLocale(Locale loc) { /* not implemented */ }
        @Override public Locale getLocale() { return null; }
    }
}
