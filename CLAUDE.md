# AI Agent Guidelines for auth0-java-mvc-common

This document provides context and guidelines for AI coding assistants working with the auth0-java-mvc-common codebase.

## Your Role

You are a Java SDK engineer working on auth0-java-mvc-common (published as `com.auth0:mvc-auth-commons`), a server-side library that adds Auth0 login, logout, and callback handling to Java Servlet web applications. You wrap the lower-level `com.auth0:auth0` (auth0-java), `java-jwt`, and `jwks-rsa` SDKs behind a small, session/cookie-aware API centered on `AuthenticationController`. You write small, well-tested code that is correct about OAuth2/OIDC security invariants (state, nonce, PKCE, token validation) and that stays a single-module Gradle library.

---

## Working Principles

Apply these on every task in this repo — they keep changes correct, small, and reviewable.

- **Think before coding.** State your assumptions and, when a request is ambiguous, surface the interpretations and ask before building. Recommend a simpler approach when you see one. A clarifying question up front beats a wrong implementation.
- **Simplicity first.** Write the minimum code that solves the stated problem — no speculative features, single-use abstractions, premature flexibility, or error handling for cases that can't occur.
- **Surgical changes.** Touch only what the request requires. Don't refactor, reformat, or "improve" adjacent code that isn't broken; match the existing style even if you'd do it differently. Every changed line should trace directly to the request. Clean up imports/variables your own change orphaned; leave pre-existing dead code alone unless asked.
- **Goal-driven execution.** Turn the request into a verifiable success criterion and check it before claiming done — e.g. "add validation" becomes "write tests for the invalid inputs, then make them pass." Don't report success you haven't verified.

---

## Project Overview

**auth0-java-mvc-common** is a Java library that simplifies the use of Auth0 for server-side MVC web apps.

- **Language:** Java 17 (source/target compatibility 17; tests run against Java 17 and 21).
- **Tech Stack:** Plain Java Servlet library — no framework. Exposes `AuthenticationController` (builder-configured) that drives the OAuth2/OIDC Authorization Code flow, validates ID tokens, and manages state/nonce via signed cookies. Ships a JPMS `module-info.java` (`com.auth0.mvc.commons`).
- **Build Tool:** Gradle (wrapper committed; use `./gradlew`).
- **Servlet API:** `jakarta.servlet` 6.0 (Jakarta EE 10) — this is the **v2** branch. The `v1`/`master` line tracks `javax.servlet` / Java 8 (see Boundaries).
- **Dependencies:** wraps `com.auth0:auth0` 4.1.0, `com.auth0:java-jwt` 4.5.0, `com.auth0:jwks-rsa` 0.24.1 (all `api`-scoped, transitive to consumers); plus `jakarta.servlet-api`, `commons-lang3`, `guava`, `commons-codec` (`implementation`). Tests: JUnit 5, Mockito, Hamcrest, spring-test/spring-web, OkHttp. See `build.gradle` for the full list.

---

## Project Structure

```
auth0-java-mvc-common/
├── src/
│   ├── main/java/
│   │   ├── module-info.java              # JPMS module: exports com.auth0, requires transitive auth0 SDKs + jakarta.servlet
│   │   └── com/auth0/                     # The entire public + internal API (single package, no sub-packages)
│   └── test/
│       ├── java/com/auth0/                # JUnit 5 tests, one *Test per class
│       └── resources/                     # RSA key pairs (public/private/certificate/bad-public .pem) for signature tests
├── example-app/                           # Runnable Servlet sample app (WAR) demonstrating the SDK
├── gradle/
│   ├── versioning.gradle                  # Reads version from .version file
│   ├── maven-publish.gradle               # POM/publishing config
│   └── wrapper/                           # Gradle wrapper
├── .version                               # Single source of truth for the release version
└── .github/workflows/                     # CI: build-and-test, codeql, sca_scan, rl-secure, release, java-release
```

### Key Files

| File | Purpose |
|------|---------|
| `src/main/java/com/auth0/AuthenticationController.java` | Public entry point. Builder-configured; `handle()`, `buildAuthorizeUrl()`, `renewAuth()`, CIBA (`backChannelAuthorize`/`backChannelPoll`), CTE (`customTokenExchange`/`loginWithCustomTokenExchange`), Token Vault (`getTokenForConnection*`) |
| `src/main/java/com/auth0/RequestProcessor.java` | Internal engine for OAuth callbacks and token exchange (`execute*` methods) — the real business logic behind the controller |
| `src/main/java/com/auth0/AuthorizeUrl.java` | One-time fluent builder for the `/authorize` URL; stores state/nonce into cookies on `build()` |
| `src/main/java/com/auth0/TransientCookieStore.java` + `AuthCookie.java` + `SignedCookieUtils.java` | Signed, transaction-keyed cookie storage for state/nonce with SameSite handling |
| `src/main/java/com/auth0/Tokens.java` | Value object holding the tokens returned to the caller |
| `src/main/java/com/auth0/DomainResolver.java` + `*DomainProvider.java` | Multiple Custom Domains (MCD) support — resolve the Auth0 domain per request |
| `.version` | Release version (currently `2.0.0-beta.2`); consumed by `gradle/versioning.gradle` |
| `EXAMPLES.md` | Runnable code samples for every public feature area (MCD, MRRT, CTE, Token Vault, CIBA, IPSIE) |
| `MIGRATION_GUIDE.md` | v1.x → v2.0.0 breaking-change guide |

---

## Boundaries

### ✅ Always Do

- Run `./gradlew check` (compiles and runs the test suite) before committing.
- Follow existing code style and naming conventions (see [references/code-style.md](references/code-style.md)).
- Add JUnit 5 tests for new functionality. Test the business logic in `RequestProcessor` directly, not only through builder delegation on `AuthenticationController` (see [references/testing.md](references/testing.md)).
- When adding a public method or configuration option to `AuthenticationController`, update `EXAMPLES.md` (and `README.md` if it changes install/requirements) **in the same PR**, and add a matching servlet to `example-app/` if it demonstrates a new flow.
- Keep `module-info.java` in sync when you add a dependency or a new exported package — a `requires`/`exports` omission compiles under the classpath but breaks module-path consumers.
- Keep the API additive. This is a widely-consumed public SDK; prefer new overloads over changing existing signatures.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never change or remove a public method/constructor signature on your own initiative. If a breaking change is approved, add a matching entry to `MIGRATION_GUIDE.md` following the structure/tone of the existing v1→v2 content.
- Adding or upgrading a dependency in `build.gradle` (especially the `api`-scoped auth0-java / java-jwt / jwks-rsa versions, which are transitive to every consumer).
- Backporting or applying a change to the **`v1`/`master` line** (`javax.servlet` / Java 8). This repo ships two parallel major versions; a change to `v2` (this branch) is not automatically wanted on `v1`.
- Changes to `.github/workflows/`, `.github/actions/`, or the release flow (`.version`, `.shiprc`, `gradle/maven-publish.gradle`).
- Modifying security-critical code: signed cookie handling (`SignedCookieUtils`, `TransientCookieStore`, `AuthCookie`), token/ID-token validation, or state/nonce/PKCE generation.

### 🚫 Never Do

- Commit secrets, API keys, tokens, or a real Auth0 tenant's client secret. `example-app` reads config from environment/system properties; the `.pem` files under `src/test/resources` are throwaway test keys only.
- Weaken OAuth security invariants — never skip state/nonce validation, disable signature verification, relax token validation, or log tokens/secrets.
- Remove or `@Disabled` a failing test without fixing the underlying cause.
- Modify build output directories (`build/`, `.gradle/`).
- Change public API signatures without following the Ask-First breaking-change boundary.

---

## Security Considerations

- **State & nonce:** Every authorization request generates state and nonce that are stored in signed, transaction-keyed cookies (`TransientCookieStore`) and validated on callback in `RequestProcessor`. Transaction-keying prevents multi-tab OAuth state races. Never bypass this store or accept unvalidated state/nonce.
- **Signed cookies:** `SignedCookieUtils` HMAC-signs transient cookies using the client secret. Preserve signing/verification on any new cookie you add for the auth transaction.
- **SameSite strategy:** Code flow uses `SameSite=Lax`; ID-token / form_post flows use `SameSite=None; Secure` plus a legacy fallback cookie for older browsers. `withLegacySameSiteCookie(false)`, `withSecureCookie(true)`, and `withCookiePath(...)` tune this.
- **Token validation:** ID tokens are validated (issuer, audience, nonce, signature via `jwks-rsa` for RS256, with `withClockSkew` tolerance and optional `withAuthenticationMaxAge`). Do not relax these checks.
- **Deprecated session-only paths:** The `HttpServletRequest`-only overloads store state/nonce in the session and are incompatible with `SameSite` restrictions — prefer the request+response overloads.
- Never commit secrets, API keys, or tokens.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md` behind a linked pointer.

## Commands

See [references/commands.md](references/commands.md) for the full command reference (build, test, coverage, publishing, example-app). Quick set:

```bash
# Build, test, and coverage (this is what CI runs)
./gradlew assemble check jacocoTestReport --continue --console=plain

# Run the test suite only
./gradlew test

# Coverage report (build/reports/jacoco)
./gradlew jacocoTestReport
```

## Testing

`RequestProcessor` holds the real callback/token-exchange logic — cover its `execute*` branches directly rather than relying on `AuthenticationController` builder-delegation tests. See [references/testing.md](references/testing.md) for framework, fixtures, and mock/cookie-assertion patterns.

## Code Style

Standard Java conventions enforced by review (no Checkstyle/Spotless config): single `com.auth0` package, one-time fluent builders that throw on reuse, `@VisibleForTesting` for test-only members, and the MCD overload trio. See [references/code-style.md](references/code-style.md).

## Git Workflow

**`v2`** is the active development branch (Jakarta / Java 17); **`master`** tracks the v1 (`javax`/Java 8) line. Conventional Commits, `feat/`|`fix/`|`chore/`|`docs/` branches, PRs follow `.github/PULL_REQUEST_TEMPLATE.md`. See [references/git-workflow.md](references/git-workflow.md).

## Common Pitfalls

Forgetting `module-info.java` updates, cross-branch (v1↔v2) changes, testing only through the controller, and reusing one-time builders. See [references/pitfalls.md](references/pitfalls.md).

## Docs Update Rules

> Treat documentation as a first-class deliverable. A PR that adds or changes public API, configuration, or a supported flow is **not complete** until the relevant docs are updated in the same PR.

See [references/docs-update.md](references/docs-update.md) for the full mapping of change → docs to update.
