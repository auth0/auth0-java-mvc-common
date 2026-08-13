# Git Workflow

## Branches

- **`v2`** is the active development branch for the current (Jakarta / Java 17) major version — the base for most PRs here.
- **`master`** tracks the v1 line (`javax.servlet` / Java 8).
- The two majors diverge on `jakarta` vs `javax` and Java 17 vs 8. A change on one branch is **not** automatically wanted on the other — see the **Ask First** boundary in `CLAUDE.md`.
- Feature branches: `feat/<short-description>`, `fix/<short-description>`, `chore/<short-description>`, `docs/<short-description>`.

## Commits

Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`), matching `git log` history.

## Pull requests

Follow `.github/PULL_REQUEST_TEMPLATE.md` — fill in **Changes**, **References**, **Testing**, and check the coverage/testing/contribution boxes.

## Releases

Driven by `.version` + `.shiprc` (ship-cli) and the `release.yml` → `java-release.yml` workflows. `.shiprc` bumps `README.md`, `.version`, and the `version` line in `build.gradle`. Publishing config lives in `gradle/maven-publish.gradle`. Don't hand-edit release artifacts — see the **Ask First** boundary in `CLAUDE.md`.
