# live-python-source-only

Scanner reports captured unmodified from a live external-consumer run:
`IamRitz/ssd-scratch-consumer`, branch `test/python-source-only`, Actions run
35202539930 (framework at `56c575b`), artifact `dependency-scan-reports`.

- `pip-audit.json` — pip-audit 2.10.1. `requests 2.32.5` reports `PYSEC-2026-2275`
  (aliases `GHSA-gc5v-m9x4-r6x2`, `CVE-2026-25645`) twice; no severity.
- `osv-scanner.json` — OSV-Scanner v2.4.0. `requests 2.32.5` has both
  `PYSEC-2026-2275` and `GHSA-gc5v-m9x4-r6x2` (CVSS 5.5 / 4.4); `idna 3.9.0` has
  both `PYSEC-2026-215` and `GHSA-65pc-fj4g-8rjx` (alias `CVE-2026-45409`).
  `requirements.txt` appears as two separate sources.

That run showed one developer-visible vulnerability per package as 1 BLOCK plus
4 LOG entries. These files are the regression fixture for advisory correlation
(test/advisory-correlation.test.js). Do not edit them: their value is that they
are real scanner output.
