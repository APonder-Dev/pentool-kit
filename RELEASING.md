# Releasing pentool

Releases are automated by `.github/workflows/release.yml`, which fires on any
`v*` tag and runs four **independent** jobs: build, GitHub Release, PyPI publish,
and GHCR container push. A failure in one (e.g. PyPI not yet configured) does not
block the others.

## One-time setup

### PyPI (Trusted Publishing — no token needed)

1. Create the project owner account on <https://pypi.org>.
2. Go to **Your projects → Publishing → Add a pending publisher** and enter:
   - **PyPI project name:** `pentool-kit` (must match `name` in `pyproject.toml`)
   - **Owner:** `APonder-Dev`
   - **Repository:** `pentool-kit`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
3. In the GitHub repo, create an **Environment** named `pypi`
   (Settings → Environments → New environment). Optionally add required reviewers.

No API token or secret is stored — the workflow authenticates via OIDC.

> If `pentool-kit` is taken on PyPI, change `name` in `pyproject.toml` to an
> available name and use that name in the pending publisher above.

### GHCR (container registry)

Nothing to configure — the workflow authenticates with the built-in
`GITHUB_TOKEN` and pushes to `ghcr.io/aponder-dev/pentool-kit`. After the first
publish, set the package visibility (public/private) under the repo's
**Packages** tab if desired.

## Cutting a release

1. Bump the version in `pyproject.toml` and `pentool/__init__.py` (keep them in sync).
2. Update `CHANGELOG.md`: add a new `## [X.Y.Z] - YYYY-MM-DD` section describing
   the changes, and add the matching link reference at the bottom of the file.
3. Commit the version bump and changelog together.
4. Tag and push (use the real version, e.g. `v1.1.2`):

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

5. Watch the **Actions** tab. On success you get:
   - a **GitHub Release** with auto-generated notes + `sdist`/`wheel` attached,
   - the package on **PyPI** (`pip install pentool-kit`),
   - the image on **GHCR** (`docker run ghcr.io/aponder-dev/pentool-kit ...`).

## Versioning

Follows [SemVer](https://semver.org): `MAJOR.MINOR.PATCH`. Keep the version in
`pyproject.toml` and `pentool/__init__.py` in sync (CI has no auto-bump).
