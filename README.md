# lockscan

Checks the packages a JavaScript lockfile installs against the
[OSV](https://osv.dev) vulnerability database, and reports each advisory
with its severity and the nearest version that fixes it.

It reads the lockfile, not `node_modules`, so it needs no install and no
Node.js, and it answers for exactly the versions the lockfile pins.

```
$ lockscan
pnpm-lock.yaml: 45 packages, 12 advisories in 3 packages

CRITICAL  lodash@3.10.1       GHSA-jf85-cpcp-j695  Prototype Pollution in lodash  (fixed in 4.17.12)
HIGH      lodash@4.17.20      GHSA-35jh-r3h4-6jhm  Command Injection in lodash  (fixed in 4.17.21)
...
```

## Lockfiles

| Package manager | File | Versions |
|---|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json` | 1, 2, 3 |
| pnpm | `pnpm-lock.yaml` | 5.x, 6.x, 9.x |
| Yarn | `yarn.lock` | classic (v1), Berry (v2 and later) |

Given a directory, lockscan reads the first of `npm-shrinkwrap.json`,
`package-lock.json`, `pnpm-lock.yaml` and `yarn.lock` it finds there.

What each reader handles:

- **Aliases.** `"my-lodash": "npm:lodash@4"` is checked as `lodash`, the name
  advisories use. npm records the real name in `name` (v2, v3) or in an
  `npm:` version (v1); pnpm keys it by the real name; Yarn writes it after
  `npm:` in the specifier.
- **Scoped packages**, `@scope/name`, in every format.
- **pnpm peer suffixes**: `_react@17.0.2` (5.x) and `(react@18.2.0)` (6.x, 9.x)
  are not part of the version.
- **Nested installs**: two versions of one package are both checked.
- **What is left out**: workspace members, links, local directories and
  tarballs, and git dependencies. They have no registry name and version to
  look up.

## Install

```
cargo install --git https://github.com/mertcanaltin/lockscan
```

## Use

```
lockscan [PATH] [--json] [--min-severity low|moderate|high|critical]
                [--ignore ID]... [--list] [--osv-url URL]
```

- `--json` prints the findings as JSON: id, aliases, severity, summary and the
  fixed version for each affected package.
- `--min-severity` leaves out advisories below a level. Advisories without a
  severity label are reported as `UNKNOWN` and kept only when no level is
  given; lockscan does not derive one from a CVSS vector.
- `--ignore` leaves out an advisory by its id or one of its aliases, such as a
  CVE number.
- `--list` prints the packages read from the lockfile and queries nothing.
- `--osv-url` points at another OSV-compatible API.

The exit status is 0 when no advisory affects the lockfile, 1 when one does,
and 2 when the scan could not finish, so it can gate a CI job:

```yaml
- run: lockscan --min-severity high
```

## How it works

All packages go to OSV's `/v1/querybatch` in batches of 1000, which answers
with the ids of the advisories affecting each one. Each advisory is then
fetched once from `/v1/vulns/{id}`, on eight threads, for its summary,
severity and ranges. The fixed version is the lowest `fixed` event above the
installed version, among the ranges for that package.

## Checked against

- The readers, against independent parsers on real lockfiles: js-yaml for
  pnpm 5.4, 6.0 and 9.0 lockfiles (2,050, 1,890, 811, 336 and 45 packages),
  `@yarnpkg/lockfile` for classic `yarn.lock` files and js-yaml for Berry
  ones (1,600, 604, 497 and 482 packages). The package sets were identical.
- The findings, against `npm audit` on the same project: the same advisories.
- `cargo test` runs the readers on fixtures for every format and the binary
  end to end against a local stand-in for the OSV API, offline.

## Limits

- Only the npm ecosystem.
- Severity comes from the advisory's own label (GitHub's advisories carry
  one); records without a label are `UNKNOWN`.
- It reports advisories; it does not change the lockfile.

## License

MIT
