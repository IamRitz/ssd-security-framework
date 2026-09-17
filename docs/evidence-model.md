# Dependency evidence model

A dependency finding bundles several claims that are easy to blur together. This
document defines the one normalized representation the framework uses to keep
them apart. The gate result, the correlated issues, the PR comment, the job
summary, Slack, and any future scanner benchmarking all read these same objects.
Do not build a second interpretation next to it.

Implementation: `security/scripts/dependency-evidence.mjs`.
Tests: `test/dependency-evidence.test.js`.

## Separate facts, never merged

| Fact | Question | Where it lives | Who decides it |
| --- | --- | --- | --- |
| **Vulnerability validity** | Is the advisory real, and which versions does it cover? | the advisory database (OSV, PyPA) | out of scope, taken as the scanner reports it |
| **Advisory match** | Did a scanner match this advisory to a package@version? | raw `findings[]` | the scanner |
| **Package relationship** | Is the package declared directly, reached through a proven path, or unknown? | `correlation.issues[].evidence.relationship` | this model, from explicit evidence only |
| **Effective version** | Which version is actually in use, and does the evidence agree? | `correlation.issues[].evidence.resolution` | this model, from observations with provenance |
| **Exploitability / applicability** | Does the vulnerable code path matter to this project? | nowhere. The framework does not assess this. | not claimed |
| **Policy action** | BLOCK / EXCEPTION / LOG | raw `findings[].action`, `summary`, `verdict` | the gate, from raw findings alone |

The rendering rule follows from the table:

| Evidence state | How it is rendered |
| --- | --- |
| proven fact | stated plainly (`declared in requirements.txt (requests==2.33.0)`) |
| supported inference | stated with its source and provenance (`OSV-Scanner reported idna 3.9.0 from requirements.txt (scanner-inferred)`) |
| conflicting | every side shown; no version headlined as the one in use |
| unknown | said to be unknown |

An inference is never promoted to a fact. In particular, **a package missing from
the root manifest is not thereby transitive**. The manifest may include other
files, the package may be declared somewhere the scanners did not analyze, or the
scanner may be wrong.

## Policy is untouched

The evidence model is presentation and measurement data. It is built **after**
the verdict is fixed, from the same parsed reports, and no decision reads it:

- raw `findings`, `summary`, `verdict`, `integrity` and `breakGlass` are identical
  with and without it (asserted in test H);
- collecting it cannot throw into the gate. An unreadable manifest is recorded as
  `status: "unreadable"`, and a collector failure as `dependencyEvidence.unavailable`.
  Neither is a report-integrity failure;
- nothing is fetched from PyPI, npm or deps.dev, and no dependency is resolved.
  The model records what the reports and the checkout's manifests say.

## Run-level record: `security-gate.json` → `dependencyEvidence`

Additive, `schemaVersion: 1`. Present on every result that evaluated reports
(absent on a report-integrity result).

```jsonc
"dependencyEvidence": {
  "schemaVersion": 1,
  "manifests": [{
    "path": "requirements.txt",          // repository-relative
    "ecosystem": "PyPI",
    "format": "requirements.txt",
    "status": "parsed",                  // parsed | missing | unreadable
    "declarations": [
      { "package": "requests", "requirement": "requests==2.33.0", "exactVersion": "2.33.0", "line": 1 }
    ],
    "unparsed": [{ "line": 2, "text": "-r dev.txt" }]   // optional: includes, editables, URLs, paths
  }],
  "observations": [{
    "scanner": "pip-audit",              // pip-audit | osv-scanner
    "ecosystem": "PyPI",
    "package": "idna",
    "version": "3.19",                   // null when the scanner gave none
    "provenance": "scanner-resolved",    // see "Version provenance"
    "source": "requirements.txt",        // repository-relative when inside the checkout, else as reported; null when unknown
    "advisoryIds": []                    // ids and aliases this scanner reported for this package at this source
    // "dependencyPaths": [["requests", "idna"]]   // optional, only when a report carries explicit paths
  }],
  "unavailable": "..."                   // only when collection failed; issues then fall back to the raw findings
}
```

`observations` holds **every** package each scanner listed, including packages
it reported as clean. That is what makes a disagreement visible: pip-audit
listing `idna 3.19` with no advisory is evidence about `idna`, even though it
produces no finding.

Coverage per scanner, which matters when reading an absence:

- **pip-audit** lists every dependency it audited, vulnerable or not. A package
  missing from it was not audited.
- **OSV-Scanner**, as the workflow invokes it (`scan source --format=json`), lists
  only packages with vulnerabilities; the live captures in `__fixtures__` show
  exactly that. A package missing from it says nothing about its version.

Manifests are read only when a scanner named them as a source (pip-audit's
`requirements.txt`, or an OSV-Scanner source whose file name matches
`requirements*.txt`), and only inside the checkout. The workflow mounts the
checkout at `/repo` for OSV-Scanner, so `/repo/requirements.txt` maps to
`requirements.txt`.

## Per-issue object: `correlation.issues[].evidence`

Every package-scoped issue (pip-audit, or OSV-Scanner with an ecosystem) carries:

```jsonc
"evidence": {
  "schemaVersion": 1,
  "package": "idna",
  "ecosystem": "PyPI",
  "relationship": {
    "value": "unknown",                  // direct | transitive | unknown
    "basis": "none",                     // manifest-declaration | scanner-dependency-path | none
    "declarations": [],                  // [{ manifest, requirement, exactVersion, line }]
    "dependencyPaths": [],               // [{ path: ["requests", "idna"], scanner, source }]
    "manifestsChecked": ["requirements.txt"]  // parsed manifests the scanners analyzed for this package
  },
  "resolution": {
    "status": "conflicting",             // consistent | conflicting | unknown
    "confidence": "conflicting",         // high | medium | low | conflicting
    "version": null,                     // the agreed version; only when status is consistent
    "versions": ["3.19", "3.9.0"],       // distinct observed versions
    "observations": [
      { "scanner": "pip-audit",   "version": "3.19",  "provenance": "scanner-resolved", "source": "requirements.txt", "advisoryReported": false },
      { "scanner": "osv-scanner", "version": "3.9.0", "provenance": "scanner-inferred", "source": "requirements.txt", "advisoryReported": true }
    ]
  },
  "unavailable": "..."                   // only when evidence could not be built
}
```

`advisoryReported` says whether that observation's scanner reported any of the
issue's advisory ids for the package: `true` or `false` for a scanner, `null` for
a manifest declaration. The existing `installedVersions` field keeps its old
meaning: the versions named by the issue's raw findings.

### Relationship rules

Evaluated in order. The first rule that matches wins.

1. **direct**, basis `manifest-declaration`: a parsed manifest that a scanner
   analyzed while reporting this package declares it by name. Names are compared
   per PEP 503 for PyPI and exactly for everything else. Any specifier counts,
   including a range. Only an exact `==`/`===` pin without a wildcard also yields
   a version observation.
2. **transitive**, basis `scanner-dependency-path`: a report carries an explicit
   dependency path of length ≥ 2 that ends at this package.
3. **unknown**, basis `none`: everything else. This includes a package that is
   not declared in the checked manifests.

A package that is both declared and reached by a path is `direct`, and keeps its
paths. Two further bases are reserved for future adapters and are not produced
by schema version 1: `lockfile-graph`, a parent/child graph read from a lockfile,
and `scanner-assertion`, a scanner explicitly labeling a package direct or
transitive.

### Version provenance

| Provenance | Assigned when | Strength |
| --- | --- | --- |
| `manifest-declared` | an exact pin in a declaration (`idna==3.19`) | high |
| `lockfile-resolved` | OSV-Scanner read the package from a lockfile (`poetry.lock`, `package-lock.json`, `uv.lock`, `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, …) | high |
| `environment-observed` | a version observed in an installed environment or build artifact. Reserved: no current source produces it. | high |
| `scanner-resolved` | pip-audit's reported version for the requirements file it audited | medium |
| `scanner-inferred` | OSV-Scanner's version for a non-lockfile source such as `requirements.txt`. Its report does not state how it derived the version. | low |
| `unknown` | no version, or a gate result without run-level evidence (older results) | low |

### Resolution rules

Observations are compared by version key: PEP 440 release normalization for
numeric PyPI versions (`3.9` = `3.9.0` = `03.9`), and exact string comparison
otherwise. No normalization is guessed for other ecosystems.

| Distinct versions | `status` | `confidence` |
| --- | --- | --- |
| 0 | `unknown` | `low` |
| 1 | `consistent` | the **strongest** provenance among the observations: any high → `high`, else any medium → `medium`, else `low` |
| ≥ 2 | `conflicting` | `conflicting` |

A conflict has no winner. A manifest pin does not silently override a scanner, a
lockfile does not silently override pip-audit, and neither observation is
dropped. Relationship and resolution are independent: a dependency can be
proven `direct` while its effective version is `conflicting`.

Corroboration does not raise confidence. Two scanners agreeing on a version from
an unlocked manifest stays `medium`, because both may share the same blind spot.

## Developer-facing wording

Rendered once, in `format-findings.mjs`, for every surface.

| Case | Relationship line | Remediation |
| --- | --- | --- |
| direct, consistent | `Dependency relationship: direct — declared in requirements.txt (requests==2.33.0).` | `Upgrade the direct declaration in requirements.txt (…) to a fixed version`. A `pip install '<pkg>==<fix>'` / `npm install` example is added **only** when the records name exactly one fixed version. |
| transitive, consistent | `Dependency relationship: transitive — dependency path: requests -> idna (from <scanner>).` | `Prefer updating the parent dependency requests, or your resolution constraints, so the resolver selects a fixed idna. A direct pin on a transitive package is not the default remedy.` No install command. |
| unknown, consistent | `Dependency relationship: unknown — <scanner> identified idna while analyzing requirements.txt, but the available reports do not prove which direct dependency introduced it.`, plus `idna is not declared in requirements.txt; that alone does not prove it is transitive.` when a manifest was checked | `…no direct pin is suggested. Establish the version actually resolved and the dependency or constraint that introduces it … and remediate there.` No install command. |
| any relationship, conflicting | as above, plus a **Resolution conflict** block listing every observation with scanner, version, source, provenance and whether it reported the advisory, then `The scanners disagree on the effective package version` (or `The manifest declaration and the scanner results disagree…`) and `Treat this finding as a dependency-resolution discrepancy until a lockfile, build artifact, or environment observation establishes the version actually used.` | `Do not pin <pkg> from this report … First establish the version actually resolved … then, if that version is affected, remediate through <its declaration in requirements.txt \| the dependency or constraint that brings it in>.` No install command. |

On a conflict, the headline drops the disputed version, for example
``**`idna` — CVE-2026-45409 (effective version disputed: 3.19 vs 3.9.0)**``, and
the card's single `fixedVersion` is cleared. A consistent version stays in the
headline as before.

An EXCEPTION keeps the tracked-exception explanation, and a malicious package keeps
"remove it" as its remediation. Both still show the relationship and resolution
lines. The raw scanner records ("Observed by", advisory ids, fixed versions with
their sources) remain listed under every issue.

## Using the model for benchmarking

A benchmark compares these same objects against ground truth for a known
repository. It must not re-parse scanner output into a schema of its own. Each
property maps to existing fields:

| Property | Measured from |
| --- | --- |
| advisory detection | `observations[].advisoryIds` and raw `findings[].id`/`aliases` against the known advisories |
| package identification | `observations[].package` + `ecosystem` against the known dependency set |
| version resolution | `observations[].version` + `provenance` per scanner against the installed version; `resolution.status` |
| direct/transitive classification | `relationship.value` + `basis` against the known graph (`unknown` scored as abstention, not error) |
| dependency-path accuracy | `relationship.dependencyPaths[].path` against the known graph |
| severity accuracy | raw `findings[].severity`, `severitySource`, `cvssScore` |
| fix-version accuracy | raw `findings[].fixVersions` |
| applicability false positives | an advisory matched (`advisoryReported: true`) at a version the ground truth does not install |
| false negatives | a known advisory for an installed version with no observation reporting it. Remember OSV-Scanner only lists vulnerable packages. |
| duplicate / alias inflation | `correlation.summary.rawFindings` vs `correlation.summary.issues`, and `issues[].findings` |

Scanner-specific facts belong on observations under their own scanner name, so
per-scanner scoring needs no join.

## Known evidence limitations (schema version 1)

- **No current scanner report proves ancestry.** pip-audit's JSON has no parent
  information. OSV-Scanner's `--format=json` source output has no dependency path;
  its `source.type` (`lockfile` / `unknown`) is recorded by the scanner but is not
  interpreted as a relationship. In practice, packages not declared in a checked
  manifest are therefore `unknown`, never `transitive`. The `dependencyPaths`
  contract exists for an adapter that does carry paths.
- **Only pip requirements files are parsed for declarations.** `pyproject.toml`,
  `Pipfile`, `package.json` and others are not read, so an npm or Poetry package
  cannot be proven `direct` yet. `-r`/`-c` includes are listed as `unparsed`, not
  followed.
- **pip-audit's report does not say how it derived a version.** The workflow runs
  it with `--no-deps`, yet the live report listed unpinned transitive packages.
  Its versions are labeled `scanner-resolved` (medium), not treated as installed.
- **No installed environment or build artifact is observed** in source security,
  so `environment-observed` is never produced there.
- **npm audit** findings are not package-scoped (no advisory id), so they carry no
  evidence object. npm's own `fixAvailable` target is rendered as before.
