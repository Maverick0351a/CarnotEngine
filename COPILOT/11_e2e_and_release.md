# Task 11 — E2E Run & Release Bundle
**Prompt:**
Confirm `.vscode/tasks.json` has **Run Assessment (E2E)**. Implement `scripts/build_release_bundle.sh` to zip `artifacts/assessment-*/` to `dist/`. Update `.github/workflows/release-artifacts.yml` to upload `dist/*` on version tag.

**Acceptance:**
- Tag `v0.1.0` creates a GitHub Release with bundle. WORKLOG updated.

**Status:**
- VS Code task present.
- Bundle scripts + release workflow updated to generate and upload zips.
- Need to push tag: `git tag v0.1.0 && git push origin v0.1.0`.

**Next:** Tag and verify release page assets (assessment zip(s) + manifest) appear.
