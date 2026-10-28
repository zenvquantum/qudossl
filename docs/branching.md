# Branch model

## Branches

| Branch | Purpose | Accepts |
|---|---|---|
| `main` | Release-ready trunk | Merges from `dev` only |
| `dev` | Integration branch | PRs from `feat/*` and `fix/*` |
| `feat/<topic>` | One feature or change | Direct commits by its author |
| `fix/<slug>` | Bug fix | Direct commits by its author |
| `sync/<subtree>-<version>` | One upstream subtree sync | `git subtree pull` only |
| `release/<version>-qudo-<n>` | Frozen release branch | **CVE cherry-picks only** |

All of these except `main` and `dev` are **short-lived**: cut when needed,
merged by PR, then deleted. There are no standing staging branches.

## Flow

```
feat/<topic> ──PR──> dev ──PR──> main ──branch──> release/3.5-qudo-1.0
```

Feature branches are cut from `dev` and merged back into `dev` by PR. Maintainers
review and merge; PRs are not self-merged.

## Release branch rules

Once a `release/<version>-qudo-<n>` branch is cut for a release it is
**frozen**:

- **No** upstream merges.
- **No** `git subtree pull` — ever.
- CVE cherry-picks only, using path translation:

  ```sh
  git cherry-pick -x --strategy=subtree -Xsubtree=openssl <upstream-sha>
  ```

- Any cherry-pick touching a file listed in
  `openssl/providers/fips.module.sources` changes the FIPS module and needs the
  extra review described in `CONTRIBUTING.md`.

## Upstream sync

Never on a frozen release branch. On a **short-lived `sync/` branch cut from
`dev`**, one subtree per branch, merged by PR and then deleted:

```sh
# OpenSSL
git checkout -b sync/openssl-3.5.8 dev
git fetch openssl-upstream refs/tags/openssl-3.5.8
git subtree pull --prefix=openssl openssl-upstream openssl-3.5.8 --squash
# resolve conflicts on openssl/* with normal git tooling, then PR into dev
```

Update the pin table in [vendored-versions.md](vendored-versions.md) in the same PR.

### Why a `sync/` branch and not a standing one

Two common alternatives are syncing directly on `main`, or keeping a long-lived
`vendor/openssl-3.x` staging branch. Neither is used, for two reasons.

**Syncing on `main` contradicts the branch model.** `main` accepts merges from
`dev` only, and a subtree pull can conflict heavily once Qudo edits land
in `crypto/ml_kem` and `crypto/ml_dsa`. Conflict resolution
belongs on a branch behind a PR and CI, not on the release trunk.

**A standing `vendor/openssl-3.x` has no work to do between syncs.** Syncs are
episodic — a few times a year, per upstream release. A branch that sits untouched
in between goes stale, and anyone who finds it has to work out whether it is
ahead, behind, or abandoned. On a repo where reproducibility means "one
repo, one SHA", an ambiguous long-lived branch is a liability.

A per-sync branch gives the same isolation and the same CI gate, records *which*
version it carried in its own name, and disappears when merged.

## Branch protection

Applied to `main` and `dev`:

- Require a pull request before merging
- Require at least one approving review
- Dismiss stale approvals on new commits
- Require CI status checks to pass
- No force pushes, no deletion

Frozen release branches additionally restrict who may push.

## What Qudo owns

Everything outside the two subtrees:

```sh
git ls-files | grep -v '^openssl/' | grep -v '^qudo-pqc-lib/'
```
