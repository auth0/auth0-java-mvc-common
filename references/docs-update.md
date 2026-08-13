# Docs Update Rules

> Treat documentation as a first-class deliverable. A PR that adds or changes public API, configuration, or a supported flow is **not complete** until the relevant docs are updated in the same PR.

| When this changes | Update these docs |
|-------------------|-------------------|
| Public API on `AuthenticationController` or a public request/builder class | `EXAMPLES.md` (matching section); add/update an `example-app/` servlet if it demos a flow |
| Install requirements, supported servlet/container/Java versions | `README.md` (Requirements / Installation) |
| A breaking change (Ask First + approved) | `MIGRATION_GUIDE.md`, following the structure/tone of the existing v1→v2 content |

> `CHANGELOG.md` is a release-flow artifact — not updated as part of a feature PR.
