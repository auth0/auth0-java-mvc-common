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

`AuthenticationController` has a `@VisibleForTesting` package-private constructor that takes a `RequestProcessor` (and a `getRequestProcessor()` getter). Inject a mock through it to drive the controller in tests:

```java
@Mock private RequestProcessor mockRequestProcessor;

AuthenticationController controller = new AuthenticationController(mockRequestProcessor);
when(mockRequestProcessor.process(request, response)).thenReturn(mockTokens);
// ...
verify(mockRequestProcessor).process(request, response);
```

## Cookie assertions

Cookie names are transaction-keyed (`com.auth0.state.<state>`, `com.auth0.nonce.<state>`, with a leading `_` on the legacy fallback). Match on substrings rather than the full `Set-Cookie` string:

```java
List<String> headers = response.getHeaders("Set-Cookie");
assertThat(headers, hasItem(containsString("com.auth0.state.asdfghjkl=asdfghjkl")));
assertThat(headers, hasItem(allOf(
    containsString("com.auth0.state.asdfghjkl=asdfghjkl"),
    containsString("SameSite=Lax"))));
```

## Coverage

JaCoCo (`./gradlew jacocoTestReport`) emits XML + HTML reports under `build/reports/jacoco`.
