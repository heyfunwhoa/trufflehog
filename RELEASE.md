# Release workflow: trufflehog

Owner: repository maintainer. Tracking: [KRU-186](https://linear.app/krusty/issue/KRU-186).
Shared policy: [Merge and deployment framework](https://github.com/heyfunwhoa/technical-docs-platform/blob/main/engineering/merge-deployment-framework.md) (proposed until its PR is merged). Local privacy and product rules remain authoritative.

## Deployment mode

Upstream-oriented Go fork: preserve existing tag/binary/container release workflows. Do not add a Vercel deployment or alter upstream release triggers.

## Working and releasing

1. Build a coherent change on a feature branch. Save/commit frequently; push at useful review checkpoints.
2. Open a focused PR and run the existing tests/security checks. Preview deployments remain automatic where already enabled; drafts are not assumed to suppress them.
3. Record PR number, full head SHA, check results, preview URL (or an intentional internal-only skip), smoke evidence and rollback target in the existing PR body using [.github/RELEASE_CHECKLIST.md](.github/RELEASE_CHECKLIST.md).
4. Inspect native Go CI and upstream release requirements for the exact head. No generic readiness Action is installed in this fork.
5. One designated release operator obtains owner approval, confirms the exact head and required checks, and merges the chosen PR. Do not bulk-merge unrelated PRs or bypass protection. Verify dependent PRs in order.
6. For a deployable application, wait for Vercel's existing Git integration. Do not also run a manual CLI deployment for the same merge. Confirm the merge SHA, production target, READY state, intended alias, and representative app journey. A protected login screen alone is not a successful app smoke test.
7. Record merged, deployed, and verified separately. Internal-only skips retain the prior production version: record its SHA and the intentional skip, not a new deployment.

For repos without Vercel or with disabled hosting, step 6 is not applicable; use their existing release process. The fork retains native tag release controls rather than the manual readiness Action.

## Build filtering and recovery

Keep the existing hosting/build behavior; see the local exception below.

Application code, published lessons/content, runtime data, dependencies, security/build configuration and unknown paths must build. Build skipping does not disable CI, security scans or review requirements. Missing Git history or policy errors must build normally.

For the new ignore scripts, RELEASE_FORCE_BUILD=1 forces a build when deliberately set in the build environment. Otherwise revert the ignoreCommand addition through a reviewed PR to disable filtering. Preserve existing cron/install/build settings. A production rollback must identify the previous known-good deployment and account for incompatible database changes; do not assume a code rollback reverses data migrations.

## Enforcement status

Repository configuration and tests are prepared in this PR. This document and the manual preflight are not branch protection. Required-check settings, Git production branch, environment approvals and successful hosted filtering must be verified by the release operator. No production activation or hosting permission is granted here.
