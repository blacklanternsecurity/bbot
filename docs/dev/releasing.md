# Releasing

A release is a tag a human pushes. CI never tags and never infers a version.

## When

Cut a release from `stable` once the changes you want shipped are merged there. Cut a prerelease (`-rc.N`) from `dev` to put the current integration tier in front of users.

## How

1. Open a pull request setting `version` in `pyproject.toml`, for example `3.1.0` or `3.1.0rc1`. Merge it.
2. Check out that commit and run the org release tool with the version spelled out:

```bash
release.sh v3.1.0        # stable
release.sh v3.1.0-rc.1   # prerelease, pyproject.toml says 3.1.0rc1
```

The tool lives at [blacklanternsecurity/CLA/scripts/release.sh](https://github.com/blacklanternsecurity/CLA/blob/main/scripts/release.sh). It refuses a dirty tree, a branch other than trunk, an existing tag, a tag outside `vMAJOR.MINOR.PATCH[-rc.N]`, or a tag that does not match `pyproject.toml`, shows what it will tag, and asks before pushing.

## What happens after

The tag starts `publish.yml`, which:

1. Refuses the tag unless it spells exactly the version in `pyproject.toml`.
2. Runs the full test suite.
3. Publishes to PyPI via trusted publishing.
4. Pushes the `bbot` and `bbot-full` images. Releases move `latest`, `stable`, `MAJOR.MINOR` and `MAJOR`; prereleases move `dev`.
5. Creates the GitHub Release with SPDX SBOMs attached.
