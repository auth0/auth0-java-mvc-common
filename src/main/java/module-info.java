module com.auth0.mvc.commons {

    // Public API
    exports com.auth0;

    // Auth0 SDKs
    requires transitive com.auth0.java;
    requires transitive com.auth0.jwt;
    requires transitive com.auth0.jwks;

    // Jakarta Servlet
    requires transitive jakarta.servlet;

    // Apache Commons
    requires org.apache.commons.lang3;
    requires org.apache.commons.codec;

    // Guava (used for @VisibleForTesting)
    requires com.google.common;
}
