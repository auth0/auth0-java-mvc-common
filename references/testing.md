# Testing

## Framework & tooling

- **JUnit 5** (`useJUnitPlatform()`) + **Mockito** + **Hamcrest** matchers.
- Spring `MockHttpServletRequest` / `MockHttpServletResponse` (spring-test) stand in for the servlet request/response.
- OkHttp is available in tests for HTTP-level assertions.
- Tests run against Java 17 and Java 21 (see `testInJavaVersions` in `build.gradle`).

## Layout & conventions

- **Location:** `src/test/java/com/auth0/` — one `*Test` class per production class.
- **Custom matchers:** `IdentityVerificationExceptionMatcher` and `InvalidRequestExceptionMatcher` for exception assertions.
- **Fixtures:** RSA key pairs in `src/test/resources/*.pem` back the RS256 signature-verification tests. `bad-public.pem` covers the signature-mismatch failure path.

## Cover `RequestProcessor` directly

`RequestProcessor` holds the real callback/token-exchange logic (`execute*` methods). Exercise its branches directly rather than relying only on `AuthenticationController` builder-delegation tests — delegation tests confirm wiring, not behavior.

## Typical mock setup

```java
@Mock private AuthAPI client;

AuthenticationController.Builder builderSpy =
    spy(AuthenticationController.newBuilder(domain, clientId, clientSecret));
doReturn(client).when(builderSpy).createAPIClient(...);
```

## Cookie assertions

```java
List<String> headers = response.getHeaders("Set-Cookie");
assertThat(headers, hasItem("com.auth0.state=value; HttpOnly; Max-Age=600; SameSite=Lax"));
```

## Coverage

JaCoCo (`./gradlew jacocoTestReport`) emits XML + HTML reports under `build/reports/jacoco`.
