# Copilot Instructions for auth0-java-mvc-common

## Overview

This is an Auth0 SDK for Java Servlet applications that simplifies OAuth2/OpenID Connect authentication flows. The library provides secure cookie-based state/nonce management and handles both Authorization Code and Implicit Grant flows.

## Core Architecture

### Main Components

- **`AuthenticationController`**: Primary entry point with Builder pattern for configuration
- **`RequestProcessor`**: Internal handler for OAuth callbacks and token processing
- **`AuthorizeUrl`**: Fluent builder for constructing OAuth authorization URLs
- **Cookie Management**: Custom `AuthCookie`/`TransientCookieStore` for SameSite cookie support

### Key Design Patterns

- **Non-reusable builders**: `AuthenticationController.Builder` throws `IllegalStateException` if `build()` called twice
- **One-time URL builders**: `AuthorizeUrl` instances cannot be reused (throws on second `build()`)
- **Fallback authentication storage**: State/nonce stored in both cookies AND session for compatibility

## Critical Cookie Handling

The library implements sophisticated cookie management for browser compatibility:

### SameSite Cookie Strategy

- **Code flow**: Uses `SameSite=Lax` (single cookie)
- **ID token flows**: Uses `SameSite=None; Secure` with legacy fallback cookie (prefixed with `_`)
- **Legacy fallback**: Automatically creates fallback cookies for browsers that don't support `SameSite=None`

### Cookie Configuration

```java
// Configure cookie behavior
.withLegacySameSiteCookie(false)  // Disable fallback cookies
.withSecureCookie(true)           // Force Secure attribute
.withCookiePath("/custom")        // Set cookie Path attribute
```

## Builder Pattern Usage

### Standard Authentication Controller Setup

```java
AuthenticationController controller = AuthenticationController.newBuilder(domain, clientId, clientSecret)
    .withJwkProvider(jwkProvider)     // Required for RS256
    .withResponseType("code")         // Default: "code"
    .withClockSkew(120)              // Default: 60 seconds
    .withOrganization("org_id")       // For organization login
    .build();
```

### URL Building (Modern Pattern)

```java
// CORRECT: Use request + response for cookie storage
String url = controller.buildAuthorizeUrl(request, response, redirectUri)
    .withState("custom-state")
    .withAudience("https://api.example.com")
    .withParameter("custom", "value")
    .build();
```

## Response Type Behavior

- **`code`**: Authorization Code flow, uses `SameSite=Lax` cookies
- **`id_token`** or **`token`**: Implicit Grant, requires `SameSite=None; Secure` + fallback cookies
- **Mixed**: `id_token code` combinations follow implicit grant cookie rules

## Testing Patterns

### Mock Setup

```java
// Standard test setup pattern
@Mock private AuthAPI client;
@Mock private IdTokenVerifier.Options verificationOptions;
@Captor private ArgumentCaptor<SignatureVerifier> signatureVerifierCaptor;

AuthenticationController.Builder builderSpy = spy(AuthenticationController.newBuilder(...));
doReturn(client).when(builderSpy).createAPIClient(...);
```

### Cookie Assertions

```java
// Verify cookie headers in tests
List<String> headers = response.getHeaders("Set-Cookie");
assertThat(headers, hasItem("com.auth0.state=value; HttpOnly; Max-Age=600; SameSite=Lax"));
```

## Development Workflow

### Build & Test

```bash
./gradlew build          # Build with Gradle wrapper
./gradlew test           # Run tests
./gradlew jacocoTestReport  # Generate coverage
```

### Key Dependencies

- **Auth0 Java SDK**: Core Auth0 API client (`com.auth0:auth0`)
- **java-jwt**: JWT token handling (`com.auth0:java-jwt`)
- **jwks-rsa**: RS256 signature verification (`com.auth0:jwks-rsa`)
- **Servlet API**: `javax.servlet-api` (compile-only)

## Migration Considerations

### Deprecated Methods

- `handle(HttpServletRequest)`: Session-based, incompatible with SameSite restrictions
- `buildAuthorizeUrl(HttpServletRequest, String)`: Session-only storage

### Modern Alternatives

- Use `handle(HttpServletRequest, HttpServletResponse)` for cookie-based auth
- Use `buildAuthorizeUrl(HttpServletRequest, HttpServletResponse, String)` for proper cookie storage

## Common Integration Points

- Organizations: Use `.withOrganization()` and validate `org_id` claims manually
- Custom parameters: Use `.withParameter()` on AuthorizeUrl (but not for `state`, `nonce`, `response_type`)
- Error handling: Catch `IdentityVerificationException` from `.handle()` calls
- HTTP customization: Use `.withHttpOptions()` for timeouts/proxy configuration
