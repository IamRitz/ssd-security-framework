# live-requests-2-33-0

Scanner reports captured unmodified from a live external-consumer run:
`IamRitz/ssd-scratch-consumer`, branch `test/python-source-only`, commit
`064c69c` (`requirements.txt` is exactly `requests==2.33.0`), Actions run
35214928623 (framework pinned at `fdd77b9`), artifact `dependency-scan-reports`.

- `pip-audit.json` — pip-audit 2.10.1. Lists `requests 2.33.0`,
  `charset-normalizer 3.5.1`, `idna 3.19`, `urllib3 2.8.0`, `certifi 2026.7.22`,
  all with no vulnerabilities.
- `osv-scanner.json` — OSV-Scanner v2.4.0. One source, `/repo/requirements.txt`
  (`type: unknown`), one package: `idna 3.9.0` with `PYSEC-2026-215` and
  `GHSA-65pc-fj4g-8rjx` (both alias `CVE-2026-45409`, CVSS 6.9 -> LOG).

The two scanners disagree about the effective `idna` version (3.19 vs 3.9.0),
and neither report records which direct dependency brought `idna` in. That run
rendered "`idna` 3.9.0 — upgrade to 3.15" as though 3.9.0 were established.
These files are the regression fixture for dependency evidence
(test/dependency-evidence.test.js); the test writes the consumer's
`requirements.txt` into a temporary checkout. Do not edit them: their value is
that they are real scanner output.
