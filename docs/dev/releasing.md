# Releasing

Nobody pushes a tag. A release is a reviewed merge into `stable` that changes `version`, approved by a `bbot-leads` member. The [publishing policy](https://github.com/blacklanternsecurity/.github/blob/main/standards/releases.md) is the source of truth. This page is how it applies to BBOT.

## How

1. Open a pull request into `stable` that sets `version` in `pyproject.toml` to a new `MAJOR.MINOR.PATCH`. The `stable guard` check refuses anything else, and refuses git or URL dependencies.
2. Merge it after review. The push to `stable` starts `publish.yml`.
3. Approve the `release` environment when GitHub asks. A release asks more than once, because each publishing job waits for its own approval: the release check, the Docker build, PyPI, and the GitHub release.

A merge into `stable` that keeps the version publishes nothing.

## What happens after

`publish.yml`:

1. Reads the version from `pyproject.toml`. If `v<version>` is already tagged it stops. If the version is on PyPI or Docker Hub with no tag, it fails: re-run the release that published it, or bump the version.
2. Runs the full test suite.
3. Builds every tracked `Dockerfile*` into `blacklanternsecurity/bbot` on Docker Hub. `Dockerfile` gets plain tags, `Dockerfile.full` the same tags with a `-full` suffix. Every release moves `latest`, `stable`, `MAJOR.MINOR` and `MAJOR`.
4. Publishes to PyPI via trusted publishing.
5. Creates the `v<version>` tag and the GitHub Release on the merged commit, with SPDX SBOMs attached.

## Dev builds

Every push to `dev` builds `ghcr.io/blacklanternsecurity/bbot:dev` and `:dev-full`. There are no prereleases on PyPI. Install `dev` with `pipx install git+https://github.com/blacklanternsecurity/bbot@dev`.
