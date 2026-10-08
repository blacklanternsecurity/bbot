# Releasing

A release is a tag a human pushes. CI never tags and never infers a version. Nothing publishes on a branch push, including the `dev` image.

## When

Cut a release from `stable` once the changes you want shipped are merged there. Cut a prerelease (`-rc.N`) from `dev` to put the current integration tier in front of users. A prerelease is the only thing that moves the `dev` image.

## How

1. Open a pull request setting `version` in `pyproject.toml`, for example `3.1.0` or `3.1.0rc1`. Merge it.
2. Check out `stable` (release) or `dev` (prerelease), pull so it equals the remote, and run the org release tool with the version spelled out:

```bash
release.sh v3.1.0        # on stable
release.sh v3.1.0-rc.1   # on dev, pyproject.toml says 3.1.0rc1
```

The tool lives at [blacklanternsecurity/CLA/scripts/release.sh](https://github.com/blacklanternsecurity/CLA/blob/40c6e18c0a6e32116eea4f89fc826f53c70889dc/scripts/release.sh), the same CLA commit the workflows pin. Run it from a CLA checkout, it needs its sibling `manifest.py`, plus `uv` and `jq`. It refuses a dirty tree, a branch other than `stable` for releases or `dev` for prereleases, a local branch behind the remote, an existing tag, a tag outside `vMAJOR.MINOR.PATCH[-rc.N]`, or a tag that does not match `pyproject.toml`, shows what it will tag, and asks before pushing.

## What happens after

The tag starts `publish.yml`, which:

1. Refuses the tag unless it spells exactly the version in `pyproject.toml`.
2. Runs the full test suite.
3. Publishes to PyPI via trusted publishing.
4. Builds every tracked `Dockerfile*` into `blacklanternsecurity/bbot`. `Dockerfile` gets plain tags, `Dockerfile.full` gets the same tags with a `-full` suffix. Releases move `latest`, `stable`, `MAJOR.MINOR` and `MAJOR`. Prereleases move `dev`.
5. Creates the GitHub Release with SPDX SBOMs attached.
