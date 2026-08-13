# Common Pitfalls

- **Forgetting `module-info.java`.** Adding a dependency or exported package without updating `module-info.java` compiles fine on the classpath but breaks module-path consumers. Keep `requires`/`exports` in sync.
- **Cross-branch changes.** Applying a v2-only change to the `v1`/`master` line (or vice versa) without being asked. The majors diverge on `jakarta` vs `javax` and Java 17 vs 8.
- **Testing only through the controller.** Relying on `AuthenticationController` builder-delegation tests misses the real branches in `RequestProcessor` (`execute*`). Cover `RequestProcessor` directly.
- **Reusing a one-time builder.** `AuthorizeUrl` and `AuthenticationController.Builder` throw `IllegalStateException` on a second `build()`.
- **Deprecated session-only overloads.** The `HttpServletRequest`-only `handle`/`buildAuthorizeUrl` overloads store state/nonce in the session and are incompatible with `SameSite` restrictions — prefer the request+response overloads.
- **Weakening security invariants.** Never skip state/nonce validation, disable signature verification, relax token validation, or log tokens/secrets.
