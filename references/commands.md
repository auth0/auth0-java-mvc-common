# Commands

All commands use the committed Gradle wrapper (`./gradlew`) from the repo root. Requires JDK 17.

## Build & test

```bash
# Build, test, and coverage (this is what CI runs)
./gradlew assemble check jacocoTestReport --continue --console=plain

# Compile + run the full test suite
./gradlew check

# Run the test suite only
./gradlew test

# Build the artifact (jar) without running tests
./gradlew assemble

# Clean build outputs
./gradlew clean
```

## Coverage

```bash
# Generate the JaCoCo report (XML + HTML) under build/reports/jacoco
./gradlew jacocoTestReport
```

## Publishing

Publishing is driven by CI (`release.yml` → `java-release.yml`) and configured in `gradle/maven-publish.gradle`; the release version is read from `.version`. Do not publish or hand-edit release artifacts locally — see the **Ask First** boundary in `CLAUDE.md`.

## Example app

`example-app/` is a runnable Servlet sample (WAR) that consumes the SDK and demonstrates the login/callback/logout flows. It reads Auth0 config from environment/system properties — never commit real tenant credentials.
