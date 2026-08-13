# Code Style

Standard Java conventions enforced by review (no Checkstyle/Spotless config in the repo).

## Naming & layout

- `UpperCamelCase` types, `lowerCamelCase` members.
- One public class per file.
- Everything lives in the single `com.auth0` package (no sub-packages).

## Builders

- **Configuration builder:** `AuthenticationController.Builder` (created via `AuthenticationController.newBuilder(...)`).
- **One-time fluent request builders:** `AuthorizeUrl` and the `*Request` classes (`RenewAuthRequest`, `TokenExchangeRequest`, `ConnectionTokenRequest`, `BackChannelAuthorizeRequest`, `BackChannelTokenRequest`).
- These throw `IllegalStateException` on reuse (second `build()`). **Preserve that guard when adding a new builder.**

```java
AuthenticationController controller =
    AuthenticationController.newBuilder(domain, clientId, clientSecret)
        .withJwkProvider(jwkProvider)   // required for RS256
        .withClockSkew(120)             // default 60s
        .build();
```

## Visibility for tests

`@VisibleForTesting` (Guava) marks package-private members exposed only for tests.

## MCD overload trio

New public methods that vary only by how the Auth0 domain is supplied follow the existing overload pattern:

```java
foo(...);                          // uses the configured domain
foo(..., String domain);           // explicit domain
foo(..., HttpServletRequest req);  // resolve domain per request (MCD)
```

## Additive API

This is a widely-consumed public SDK. Prefer new overloads over changing existing signatures; keep the API additive.
