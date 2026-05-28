# Migrating from v1.x to v2.0.0

This guide covers the changes required to migrate your application from `mvc-auth-commons` v1.x to v2.0.0.

## Overview of Changes

v2.0.0 is a major release that includes:

- **Platform upgrade:** Java 17 minimum, Jakarta Servlet 6.0 (replaces `javax.servlet`)
- **Security hardening:** HMAC-signed origin domain cookies bound to state, ID Token signature always verified, algorithm auto-detection
- **Deprecated API removal:** Session-based methods and classes removed
- **ID Token validation rewrite:** Delegated to `auth0-java` v3 (removes custom verification stack)
- **Multi-tab login fix:** Transaction-keyed cookies prevent concurrent login race conditions
- **JPMS module support:** Declared as `com.auth0.mvc.commons` module
- **Dependency upgrades:** auth0-java v3.5.1, java-jwt v4.5.0, jwks-rsa v0.24.1, Gradle 8.x

---

## Requirements

| | v1.x | v2.0.0 |
|---|---|---|
| **Java** | 8+ | 17+ |
| **Servlet API** | `javax.servlet` 3.1+ | `jakarta.servlet` 6.0+ |
| **Servlet Container** | Tomcat 8.5+, Jetty 9+, WildFly 14+ | Tomcat 10.1+, Jetty 12+, WildFly 27+ |
| **auth0-java** | 1.x / 2.x | 3.x (3.5.1+) |
| **java-jwt** | 3.x | 4.x (4.5.0+) |
| **jwks-rsa** | 0.21.x | 0.24.x |
| **Spring Boot** (if applicable) | 2.x | 3.x |
| **Gradle** (if building from source) | 6.x | 8.x |

---

## Installation

Update your dependency version:

**Maven:**
```xml
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>mvc-auth-commons</artifactId>
  <version>2.0.0-beta.0</version>
</dependency>
```

**Gradle:**
```groovy
implementation 'com.auth0:mvc-auth-commons:2.0.0-beta.0'
```

---

## Breaking Changes

### 1. Namespace: `javax.servlet` to `jakarta.servlet`

All servlet imports must be updated:

```diff
- import javax.servlet.http.HttpServletRequest;
- import javax.servlet.http.HttpServletResponse;
- import javax.servlet.http.HttpSession;
- import javax.servlet.http.Cookie;
+ import jakarta.servlet.http.HttpServletRequest;
+ import jakarta.servlet.http.HttpServletResponse;
+ import jakarta.servlet.http.HttpSession;
+ import jakarta.servlet.http.Cookie;
```

This applies to all classes that reference `HttpServletRequest`, `HttpServletResponse`, `HttpSession`, `Cookie`, `Filter`, `Servlet`, etc.

> **Note:** If you are using Spring Boot, upgrading from Spring Boot 2.x to 3.x handles this namespace change for your application code. However, your dependency on `mvc-auth-commons` must also be upgraded to v2.

---

### 2. Removed: `handle(HttpServletRequest)`

The single-parameter `handle()` method that used the HTTP session for state management has been removed.

**Before (v1):**
```java
Tokens tokens = authController.handle(request);
```

**After (v2):**
```java
Tokens tokens = authController.handle(request, response);
```

The two-parameter version uses secure, transient cookies (instead of server-side sessions) for state and nonce storage. This is required for compatibility with SameSite cookie restrictions in modern browsers.

---

### 3. Removed: `buildAuthorizeUrl(HttpServletRequest, String)`

The two-parameter `buildAuthorizeUrl()` that used the HTTP session has been removed.

**Before (v1):**
```java
String authorizeUrl = authController.buildAuthorizeUrl(request, redirectUri).build();
```

**After (v2):**
```java
String authorizeUrl = authController.buildAuthorizeUrl(request, response, redirectUri).build();
```

The `response` parameter is required so that state and nonce cookies can be set on the response.

---

### 4. Removed: `InvalidRequestException.getDescription()`

The deprecated `getDescription()` method has been removed. Use `getMessage()` instead.

**Before (v1):**
```java
catch (InvalidRequestException e) {
    String desc = e.getDescription();
}
```

**After (v2):**
```java
catch (InvalidRequestException e) {
    String desc = e.getMessage();
}
```

---

### 5. Removed: `withHttpOptions(HttpOptions)` on Builder

The `HttpOptions` configuration on `AuthenticationController.Builder` has been removed. The underlying HTTP client is now managed by `auth0-java` v3's `DefaultHttpClient`.

**Before (v1):**
```java
HttpOptions options = new HttpOptions();
options.setConnectTimeout(10);
options.setReadTimeout(10);

AuthenticationController controller = AuthenticationController
    .newBuilder(domain, clientId, clientSecret)
    .withHttpOptions(options)
    .build();
```

**After (v2):**
```java
// HTTP client configuration is managed internally by auth0-java v3.
// If you need custom HTTP settings, configure them via AuthAPI directly.
AuthenticationController controller = AuthenticationController
    .newBuilder(domain, clientId, clientSecret)
    .build();
```

---

### 6. Removed: Custom Signature Verifier Classes

The following classes have been removed. ID Token verification is now handled internally by `auth0-java` v3's `IdTokenVerifier`:

| Removed Class | v2 Replacement |
|---|---|
| `com.auth0.IdTokenVerifier` | `com.auth0.utils.tokens.IdTokenVerifier` (internal, from auth0-java v3) |
| `com.auth0.SignatureVerifier` | `com.auth0.utils.tokens.SignatureVerifier` (internal, from auth0-java v3) |
| `com.auth0.AsymmetricSignatureVerifier` | Per-domain JwkProvider resolution (internal) |
| `com.auth0.SymmetricSignatureVerifier` | `SignatureVerifier.forHS256(clientSecret)` (internal) |
| `com.auth0.AlgorithmNameVerifier` | Removed entirely — signature is always verified |
| `com.auth0.TokenValidationException` | `com.auth0.exception.IdTokenValidationException` (from auth0-java v3) |

If your code references any of these classes directly, remove those references. The library now handles all token verification internally.

---

### 7. Removed: Session-Based Storage Classes

| Removed Class | Purpose | v2 Replacement |
|---|---|---|
| `RandomStorage` | Session-based state/nonce storage | `TransientCookieStore` (cookie-based) |
| `SessionUtils` | HTTP session utilities | Removed — cookies only |

If your code references `RandomStorage` or `SessionUtils`, remove those references. The library exclusively uses transient cookies for state management.

---

### 8. Algorithm Auto-Detection (Behavior Change)

In v1, you had to configure the signing algorithm explicitly:
- HS256 was the default for implicit flows
- RS256 required configuring a `JwkProvider`

In v2, the algorithm is read automatically from the token's `alg` header:

- **RS256 tokens:** Verified using the configured `JwkProvider`, or one auto-discovered from the domain's `/.well-known/jwks.json` endpoint
- **HS256 tokens:** Verified using the client secret

You should still configure a `JwkProvider` if you want to control caching, rate-limiting, or connection settings:

```java
JwkProvider jwkProvider = new JwkProviderBuilder("your-tenant.auth0.com")
    .cached(10, 24, TimeUnit.HOURS)
    .rateLimited(10, 1, TimeUnit.MINUTES)
    .build();

AuthenticationController controller = AuthenticationController
    .newBuilder(domain, clientId, clientSecret)
    .withJwkProvider(jwkProvider)
    .build();
```

---

### 9. auth0-java v3 API Changes

If your application imports `auth0-java` classes directly, note these changes:

| v1 (auth0-java 1.x/2.x) | v2 (auth0-java 3.x) |
|---|---|
| `new AuthAPI(domain, clientId, clientSecret)` | `AuthAPI.newBuilder(domain, clientId, clientSecret).build()` |
| `AuthAPI.authorizeUrl(redirectUri)` | Same (unchanged) |
| `AuthAPI.exchangeCode(code, redirectUri)` | Same (unchanged) |
| `TokenHolder.getIdToken()` | Same (unchanged) |

---

## What's New in v2

### MCD Security Hardening

Multiple Custom Domains (MCD) support was introduced in v1.12.0. In v2, MCD has been hardened with:

- **HMAC-signed origin domain cookie:** The origin domain is cryptographically bound to the `state` parameter using HMAC-SHA256 with the client secret. This prevents cookie replay or tampering across different authentication transactions.
- **Per-domain JwkProvider cache:** The library maintains an internal `ConcurrentHashMap<String, JwkProvider>` cache. JWKS endpoints are only contacted once per domain (per JVM lifetime). If a customer-provided `JwkProvider` is configured via `withJwkProvider()`, it takes precedence for all domains.
- **ID Token signature always verified per issuer:** In v1, the `AlgorithmNameVerifier` could skip signature verification in certain MCD code flow paths. In v2, the ID Token signature is always verified against the correct issuer's JWKS.

These improvements are transparent to application code — no changes required if you're already using MCD in v1.

---

### Transaction-Keyed Cookies (Multi-Tab Login Fix)

v1 used a single fixed cookie name (`com.auth0.state`) shared across all browser tabs. Concurrent logins would overwrite each other, causing state validation failures.

v2 embeds the state value in the cookie name, isolating each login flow:

```
# v1 — race condition: last tab wins
com.auth0.state = <last_tab_state>
com.auth0.nonce = <last_tab_nonce>

# v2 — each tab gets its own cookie
com.auth0.state.abc123 = abc123
com.auth0.nonce.abc123 = <nonce_for_abc123>
com.auth0.state.xyz789 = xyz789
com.auth0.nonce.xyz789 = <nonce_for_xyz789>
```

**Backward compatible during rolling upgrades:** On callback, v2 checks for the transaction-keyed cookie first, then falls back to the legacy fixed-name cookie for in-flight transactions that started before the upgrade.

---

### ID Token Signature Always Verified

In v1, the `AlgorithmNameVerifier` could skip signature verification in certain code flow paths. In v2, the ID Token signature is **always** verified — either via RS256 (JwkProvider) or HS256 (client secret). There is no code path that allows unverified tokens.

---

### Java Module System (JPMS) Support

v2 includes a `module-info.java` descriptor. The module name is `com.auth0.mvc.commons`:

```java
module com.auth0.mvc.commons {
    exports com.auth0;

    requires transitive com.auth0.java;
    requires transitive com.auth0.jwt;
    requires transitive com.auth0.jwks;
    requires transitive jakarta.servlet;
    requires org.apache.commons.lang3;
    requires org.apache.commons.codec;
    requires com.google.common;
}
```

If your application uses JPMS, add `requires com.auth0.mvc.commons;` to your `module-info.java`.

---

## Removed APIs — Complete Reference

### Deleted Classes

| Class | Purpose | v2 Replacement |
|---|---|---|
| `IdTokenVerifier` | Custom ID token validation | auth0-java v3's `IdTokenVerifier` (internal) |
| `SignatureVerifier` | Base class for token signature verification | Auto-detection from `alg` header (internal) |
| `AsymmetricSignatureVerifier` | RS256 signature verification | Per-domain `JwkProvider` resolution (internal) |
| `SymmetricSignatureVerifier` | HS256 signature verification | `SignatureVerifier.forHS256()` (internal) |
| `AlgorithmNameVerifier` | Algorithm allowlist check | Removed — always verifies signature |
| `TokenValidationException` | Custom validation exception | `com.auth0.exception.IdTokenValidationException` |
| `RandomStorage` | Session-based state/nonce storage | `TransientCookieStore` (cookie-based) |
| `SessionUtils` | HTTP session utilities | Removed — cookies only |

### Deleted Methods

| Class | Method | Replacement |
|---|---|---|
| `AuthenticationController` | `handle(HttpServletRequest)` | `handle(HttpServletRequest, HttpServletResponse)` |
| `AuthenticationController` | `buildAuthorizeUrl(HttpServletRequest, String)` | `buildAuthorizeUrl(HttpServletRequest, HttpServletResponse, String)` |
| `AuthenticationController.Builder` | `withHttpOptions(HttpOptions)` | Removed (auth0-java v3 manages HTTP client) |
| `InvalidRequestException` | `getDescription()` | `getMessage()` |

---

## Migration Checklist

Use this checklist to verify your migration is complete:

- [ ] **Runtime:** Upgrade Java to 17+
- [ ] **Container:** Upgrade servlet container to Jakarta EE 10 compatible (Tomcat 10.1+, Jetty 12+, WildFly 27+)
- [ ] **Imports:** Update all `javax.servlet.*` imports to `jakarta.servlet.*`
- [ ] **handle():** Replace `handle(request)` with `handle(request, response)`
- [ ] **buildAuthorizeUrl():** Replace `buildAuthorizeUrl(request, uri)` with `buildAuthorizeUrl(request, response, uri)`
- [ ] **getDescription():** Replace `InvalidRequestException.getDescription()` with `getMessage()`
- [ ] **HttpOptions:** Remove any `withHttpOptions()` calls from Builder
- [ ] **Deleted classes:** Remove references to `SignatureVerifier`, `AsymmetricSignatureVerifier`, `SymmetricSignatureVerifier`, `IdTokenVerifier`, `AlgorithmNameVerifier`, `TokenValidationException`, `RandomStorage`, `SessionUtils`
- [ ] **auth0-java:** Update `auth0-java` dependency to v3.x if used directly in your app
- [ ] **Spring Boot:** If applicable, upgrade to Spring Boot 3.x
- [ ] **JPMS:** If using Java modules, add `requires com.auth0.mvc.commons;`
- [ ] **Test:** Verify login flow works end-to-end (authorize -> callback -> tokens)
- [ ] **Test:** Verify multi-tab login works (open login in two tabs simultaneously)
- [ ] **Test:** If using MCD, verify each custom domain resolves and validates correctly

---

## Full Example (v2)

### Configuration

```java
import com.auth0.AuthenticationController;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;

import java.util.concurrent.TimeUnit;

public class Auth0Config {
    private static final String DOMAIN = "your-tenant.auth0.com";
    private static final String CLIENT_ID = "YOUR_CLIENT_ID";
    private static final String CLIENT_SECRET = "YOUR_CLIENT_SECRET";

    private static final AuthenticationController controller;

    static {
        JwkProvider jwkProvider = new JwkProviderBuilder(DOMAIN)
            .cached(10, 24, TimeUnit.HOURS)
            .rateLimited(10, 1, TimeUnit.MINUTES)
            .build();

        controller = AuthenticationController
            .newBuilder(DOMAIN, CLIENT_ID, CLIENT_SECRET)
            .withJwkProvider(jwkProvider)
            .build();
    }

    public static AuthenticationController getController() {
        return controller;
    }
}
```

### Login Servlet

```java
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(urlPatterns = {"/login"})
public class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String authorizeUrl = Auth0Config.getController()
            .buildAuthorizeUrl(req, res, "http://localhost:3000/callback")
            .withScope("openid profile email")
            .build();
        res.sendRedirect(authorizeUrl);
    }
}
```

### Callback Servlet

```java
import com.auth0.IdentityVerificationException;
import com.auth0.Tokens;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(urlPatterns = {"/callback"})
public class CallbackServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        try {
            Tokens tokens = Auth0Config.getController().handle(req, res);
            req.getSession().setAttribute("id_token", tokens.getIdToken());
            req.getSession().setAttribute("access_token", tokens.getAccessToken());
            res.sendRedirect("/dashboard");
        } catch (IdentityVerificationException e) {
            res.sendRedirect("/login?error=" + e.getCode());
        }
    }
}
```

---

## Troubleshooting

### "The received state doesn't match the expected one"

This error occurs when the state cookie is not found on callback. Common causes:

1. **Cookie blocked by SameSite policy:** Ensure your callback is served over HTTPS in production. Use `.withSecureCookie(true)` if needed.
2. **Cookie path mismatch:** If your app is deployed at a sub-path, configure `.withCookiePath("/your-app")`.
3. **Third-party cookie restrictions:** Some browsers block cookies in cross-origin iframes. Avoid embedding the login flow in an iframe.

### "Failed to get public key for key ID"

This error occurs when the JwkProvider cannot fetch the signing key. Common causes:

1. **Network connectivity:** Ensure the server can reach `https://your-tenant.auth0.com/.well-known/jwks.json`.
2. **Rate limiting:** If using the default auto-discovered JwkProvider, it has no rate limiting configured. For high-traffic apps, configure a `JwkProvider` with caching.

### ClassNotFoundException for `javax.servlet.*`

Your application or a dependency still references the old `javax.servlet` namespace. Check:
1. All your code uses `jakarta.servlet.*` imports
2. Your servlet container is Jakarta EE 10 compatible
3. No transitive dependencies pull in the old `javax.servlet-api`

---

## Support

- [API Reference (JavaDocs)](https://javadoc.io/doc/com.auth0/mvc-auth-commons)
- [Examples](./EXAMPLES.md)
- [Report an issue](https://github.com/auth0/auth0-java-mvc-common/issues)
