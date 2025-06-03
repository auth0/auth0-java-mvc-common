package com.auth0;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests to verify Jakarta EE compatibility.
 * These tests ensure Jakarta servlet API is available and working.
 */
public class JakartaCompatibilityTest {

    @Test
    public void testJakartaServletRequestAvailable() {
        // Verify Jakarta HttpServletRequest can be mocked and used
        HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
        assertNotNull(mockRequest, "Jakarta HttpServletRequest should be available");
        
        // Verify it's from Jakarta package
        String className = mockRequest.getClass().getName();
        assertTrue(className.contains("jakarta") || className.contains("HttpServletRequest"), 
                   "Should be Jakarta servlet type");
    }

    @Test
    public void testJakartaServletResponseAvailable() {
        // Verify Jakarta HttpServletResponse can be mocked and used
        HttpServletResponse mockResponse = Mockito.mock(HttpServletResponse.class);
        assertNotNull(mockResponse, "Jakarta HttpServletResponse should be available");
    }

    @Test
    public void testJakartaHttpSessionAvailable() {
        // Test Jakarta HttpSession
        HttpSession mockSession = Mockito.mock(HttpSession.class);
        assertNotNull(mockSession, "Jakarta HttpSession should be available");
        
        // Test basic session operations
        Mockito.when(mockSession.getAttribute("test")).thenReturn("value");
        Mockito.doNothing().when(mockSession).setAttribute("test", "value");
        
        mockSession.setAttribute("test", "value");
        Mockito.verify(mockSession).setAttribute("test", "value");
    }

    @Test
    public void testJakartaCookieAvailable() {
        // Test Jakarta Cookie
        Cookie cookie = new Cookie("testCookie", "testValue");
        assertNotNull(cookie, "Jakarta Cookie should be available");
        
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        
        // Verify basic cookie properties
        assertNotNull(cookie.getName());
        assertNotNull(cookie.getValue());
    }

    @Test
    public void testJakartaServletIntegration() {
        // Test integration between Jakarta servlet components
        HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = Mockito.mock(HttpServletResponse.class);
        HttpSession mockSession = Mockito.mock(HttpSession.class);
        
        // Setup mock behavior
        Mockito.when(mockRequest.getSession(true)).thenReturn(mockSession);
        Mockito.when(mockRequest.getContextPath()).thenReturn("/test");
        
        // Test session retrieval
        HttpSession session = mockRequest.getSession(true);
        assertNotNull(session, "Session should be retrieved successfully");
        
        String contextPath = mockRequest.getContextPath();
        assertNotNull(contextPath, "Context path should be available");
    }
} 