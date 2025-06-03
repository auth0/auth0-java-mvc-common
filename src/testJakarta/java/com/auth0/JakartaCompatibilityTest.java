package com.auth0;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests to verify Jakarta EE compatibility of the transformed library.
 * These tests ensure the transformed JAR correctly uses jakarta.servlet.* packages.
 */
public class JakartaCompatibilityTest {

    @Test
    public void testAuthenticationControllerBuilderCreation() {
        // Verify AuthenticationController can be created in Jakarta EE environment
        AuthenticationController.Builder builder = AuthenticationController
                .newBuilder("test.auth0.com", "testClientId", "testClientSecret");
        
        assertNotNull(builder, "AuthenticationController.Builder should be created successfully");
        
        AuthenticationController controller = builder.build();
        assertNotNull(controller, "AuthenticationController should be created successfully");
    }

    @Test
    public void testSessionUtilsWithJakartaServlet() {
        // Test SessionUtils with Jakarta Servlet API mock objects
        HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
        jakarta.servlet.http.HttpSession mockSession = Mockito.mock(jakarta.servlet.http.HttpSession.class);
        
        Mockito.when(mockRequest.getSession(true)).thenReturn(mockSession);
        
        // Verify SessionUtils.set works correctly
        SessionUtils.set(mockRequest, "testKey", "testValue");
        
        // Verify mock was called correctly
        Mockito.verify(mockSession).setAttribute("testKey", "testValue");
    }

    @Test
    public void testTransientCookieStoreWithJakartaServlet() {
        // Verify TransientCookieStore works correctly with Jakarta Servlet API
        HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = Mockito.mock(HttpServletResponse.class);
        
        // Verify TransientCookieStore.storeState executes without throwing exceptions
        try {
            TransientCookieStore.storeState(mockResponse, "testState", SameSite.LAX, true, false, "/");
            // Test passes if no exception is thrown
        } catch (Exception e) {
            throw new AssertionError("TransientCookieStore.storeState should not throw an exception", e);
        }
    }
} 