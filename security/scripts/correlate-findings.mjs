// Alias-aware correlation of decided gate findings into DEVELOPER-FACING issues.
//
// Two layers, deliberately kept apart:
//
//   findings  the raw normalized evidence, one entry per scanner record. This is
//             the POLICY input and output: every entry keeps its own source,
//             severity derivation, policy rule and action. Nothing here removes,
//             merges or rewrites one.
//   issues    a presentation grouping over those findings. Records that name the
//             same advisory for the same package are one thing to a developer
//             ("requests has CVE-2026-25645"), even when pip-audit reports it as
//             PYSEC-2026-2275 and OSV-Scanner reports it twice more, as the PYSEC
//             record and the GHSA record.
//
// IDENTITY IS EVIDENCE-BACKED ONLY. Two findings correlate when, and only when:
//
//   - both come from a package-scoped dependency source (pip-audit, OSV-Scanner),
//   - they name the same package in the same ecosystem, and
//   - their advisory identifiers are connected through each record's own `id`
//     and `aliases`. The alias graph is treated as an equivalence relation, so a
//     chain (A aliases B, B aliases C) is one identity even though A never names C.
//
// What deliberately does NOT correlate:
//
//   - two unrelated advisories on the same package (no shared identifier),
//   - the same advisory id on a different package or ecosystem (a GHSA can cover
//     several packages; each package is its own remediation),
//   - an OSV record with no ecosystem (the package scope cannot be established),
//   - npm audit findings: npm reports one entry PER PACKAGE that may aggregate
//     several advisories, and records no advisory id, so there is no identifier
//     to correlate on without guessing,
//   - secrets, SAST, image findings and integrity failures: each is its own issue.
//
// An issue's action is the STRONGEST action among its findings
// (BLOCK_DEPLOY/BLOCK > EXCEPTION > LOG). This never changes a verdict — the gate
// already decided it from the raw findings — it only stops a blocking record from
// being displayed as if it were also two separate logged ones.

const PACKAGE_SCOPED_SOURCES = new Set(['pip-audit', 'osv-scanner']);

const ACTION_RANK = { BLOCK_DEPLOY: 0, BLOCK: 0, EXCEPTION: 1, LOG: 2 };
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

export function isIntegrityFinding(finding) {
  return (
    finding?.id === 'report-integrity' ||
    (typeof finding?.policyRule === 'string' && finding.policyRule.endsWith('report_integrity'))
  );
}

// PEP 503: PyPI names compare case-insensitively with runs of -, _ and . equal.
// Every other ecosystem is compared exactly: guessing a normalization rule for
// an ecosystem would risk merging two genuinely different packages.
function normalizePackage(ecosystem, name) {
  return ecosystem === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
}

// The package scope a finding's identifiers live in, or null when the finding
// carries no package context the framework can vouch for.
function packageScope(finding) {
  if (!PACKAGE_SCOPED_SOURCES.has(finding.source) || isIntegrityFinding(finding)) {
    return null;
  }
  if (typeof finding.package !== 'string' || finding.package === '') {
    return null;
  }
  // pip-audit audits Python requirements only, so its ecosystem is a fact about
  // the scanner. OSV-Scanner records the ecosystem per package; without it the
  // scope is unknown and the finding stays on its own.
  const ecosystem = finding.source === 'pip-audit' ? 'PyPI' : finding.ecosystem;
  if (typeof ecosystem !== 'string' || ecosystem === '') {
    return null;
  }
  return { ecosystem, package: finding.package, key: `${ecosystem}\0${normalizePackage(ecosystem, finding.package)}` };
}

function identifiers(finding) {
  const ids = [finding.id, ...(Array.isArray(finding.aliases) ? finding.aliases : [])];
  return ids.filter((id) => typeof id === 'string' && id.trim() !== '').map((id) => id.trim());
}

// CVE first (the identifier most developers search for), then GHSA, then the
// rest, each alphabetically. Presentation order only.
function identifierOrder(a, b) {
  const rank = (id) => (/^CVE-/i.test(id) ? 0 : /^GHSA-/i.test(id) ? 1 : 2);
  return rank(a) - rank(b) || a.localeCompare(b);
}

function strongestAction(actions) {
  return [...actions].sort((a, b) => (ACTION_RANK[a] ?? 9) - (ACTION_RANK[b] ?? 9))[0];
}

class DisjointSet {
  constructor(size) {
    this.parent = Array.from({ length: size }, (_, index) => index);
  }

  find(index) {
    while (this.parent[index] !== index) {
      this.parent[index] = this.parent[this.parent[index]];
      index = this.parent[index];
    }
    return index;
  }

  union(a, b) {
    const rootA = this.find(a);
    const rootB = this.find(b);
    if (rootA !== rootB) {
      // Lowest index wins, so issue order follows first appearance.
      this.parent[Math.max(rootA, rootB)] = Math.min(rootA, rootB);
    }
  }
}

// Returns issues in first-appearance order. Each issue lists the indexes of the
// findings it groups; the findings themselves are never copied or modified.
export function correlateFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const sets = new DisjointSet(list.length);
  const firstHolder = new Map();

  list.forEach((finding, index) => {
    const scope = packageScope(finding);
    if (!scope) {
      return;
    }
    for (const id of identifiers(finding)) {
      // Advisory identifiers compare case-insensitively (GHSA ids appear in
      // both cases across databases); the scope keeps packages apart.
      const node = `${scope.key}\0${id.toUpperCase()}`;
      if (firstHolder.has(node)) {
        sets.union(firstHolder.get(node), index);
      } else {
        firstHolder.set(node, index);
      }
    }
  });

  const groups = new Map();
  list.forEach((_, index) => {
    const root = sets.find(index);
    if (!groups.has(root)) {
      groups.set(root, []);
    }
    groups.get(root).push(index);
  });

  return [...groups.values()].map((indexes) => describeIssue(list, indexes));
}

function describeIssue(findings, indexes) {
  const members = indexes.map((index) => findings[index]);
  const first = members[0];
  const scope = packageScope(first);
  const action = strongestAction(members.map((finding) => finding.action));
  const severities = members
    .map((finding) => (typeof finding.severity === 'string' ? finding.severity.toLowerCase() : null))
    .filter((severity) => severity in SEVERITY_RANK)
    .sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b]);

  const issue = {
    key: scope ? `${scope.key.replace('\0', ':')}:${indexes[0]}` : `finding:${indexes[0]}`,
    correlated: members.length > 1,
    action,
    integrity: members.some(isIntegrityFinding),
    findings: indexes,
    sources: [...new Set(members.map((finding) => finding.source))],
    actions: [...new Set(members.map((finding) => finding.action))]
  };

  if (scope) {
    const ids = [...new Map(members.flatMap(identifiers).map((id) => [id.toUpperCase(), id])).values()].sort(
      identifierOrder
    );
    issue.package = first.package;
    issue.ecosystem = scope.ecosystem;
    issue.advisoryIds = ids;
    issue.primaryId = ids[0];
    issue.installedVersions = [
      ...new Set(members.map((finding) => finding.installedVersion).filter((version) => typeof version === 'string'))
    ];
  } else {
    issue.primaryId = first.id;
  }
  if (severities.length > 0) {
    // The highest severity ANY record was classified at. For ordering only; each
    // record's own severity and how it was derived stays on the finding.
    issue.highestSeverity = severities[0];
  }
  issue.breakGlassEligible = members.some((finding) => finding.breakGlassEligible === true);
  return issue;
}

// Counts over issues, next to the raw finding count they were built from.
// `integrity` issues are counted once, on their own, never also as blocking.
export function summarizeIssues(issues, rawFindingCount) {
  const count = (predicate) => issues.filter(predicate).length;
  return {
    issues: issues.length,
    rawFindings: rawFindingCount,
    block: count((issue) => !issue.integrity && ACTION_RANK[issue.action] === 0),
    exception: count((issue) => !issue.integrity && issue.action === 'EXCEPTION'),
    log: count((issue) => !issue.integrity && issue.action === 'LOG'),
    integrity: count((issue) => issue.integrity)
  };
}

// The machine-readable block recorded in a gate result. Additive: `findings`
// and `summary` keep their meaning (raw per-record counts).
export function correlationRecord(findings) {
  const issues = correlateFindings(findings);
  return {
    schemaVersion: 1,
    basis: 'package-scoped advisory id + alias graph (pip-audit, osv-scanner); all other findings stand alone',
    summary: summarizeIssues(issues, Array.isArray(findings) ? findings.length : 0),
    issues
  };
}
