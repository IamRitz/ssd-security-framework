// What each delivery role must — and must not — be able to do, and an offline
// analysis of its identity policies against that.
//
// The requirements mirror what the framework's runtime actually calls:
//   push+scan  _ecr-collect.yml (docker push through amazon-ecr-login) and
//              poll-ecr-scan.mjs (describe-image-scan-findings; with enhanced
//              scanning also inspector2 list-coverage / list-findings)
//   deploy     ssm-deploy.mjs (ssm send-command AWS-RunShellScript to ONE
//              instance, get-command-invocation, which only works on "*")
//   instance   the instance pulls by digest with its OWN role (ECR auth + pull)
//
// Separation is checked as well as sufficiency: the push role must not reach
// the instance, the deploy role must not write to ECR (config.mjs already
// refuses one ARN for both; this checks what the two policies grant).
//
// BASIS: policy-document analysis of the role's inline and attached policies.
// Simulation results (iam simulate-principal-policy) are recorded beside it and
// never replace it. Neither proves runtime behaviour: SCPs, resource policies,
// session policies and VPC endpoint policies can still deny a granted action.
import { grants, statements } from './evaluate.mjs';

const ECR_PUSH = ['ecr:BatchCheckLayerAvailability', 'ecr:InitiateLayerUpload', 'ecr:UploadLayerPart', 'ecr:CompleteLayerUpload', 'ecr:PutImage'];
const ECR_PULL = ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'];
const SSM_CORE = ['ssm:UpdateInstanceInformation', 'ssmmessages:CreateControlChannel', 'ec2messages:GetMessages'];

export const arns = ({ partition = 'aws', account, region, repository, instanceId }) => ({
  repository: `arn:${partition}:ecr:${region}:${account}:repository/${repository}`,
  otherRepository: `arn:${partition}:ecr:${region}:${account}:repository/ssd-onboard-probe/not-${repository}`,
  instance: `arn:${partition}:ec2:${region}:${account}:instance/${instanceId}`,
  otherInstance: `arn:${partition}:ec2:${region}:${account}:instance/i-00000000000000000`,
  runShellScript: `arn:${partition}:ssm:${region}::document/AWS-RunShellScript`,
  otherDocument: `arn:${partition}:ssm:${region}::document/SsdOnboardProbeOtherDocument`
});

// role -> { required: [{action, resource, why}], forbidden: [{action, resource, severity, why}] }
export function roleRequirements(role, target, { enhanced = false } = {}) {
  const a = arns(target);
  if (role === 'push') {
    return {
      required: [
        { action: 'ecr:GetAuthorizationToken', resource: '*', why: 'ECR login (account-level API)' },
        ...ECR_PUSH.map((action) => ({ action, resource: a.repository, why: 'docker push to the configured repository' })),
        { action: 'ecr:DescribeImageScanFindings', resource: a.repository, why: 'poll the registry scan of the pushed digest' },
        // enhanced: true (ENHANCED), false (BASIC), null (scan type unknown:
        // the Inspector statement is POSSIBLY needed, so its absence cannot
        // pass — NOT VERIFIED — but is not proven missing either).
        ...(enhanced === false
          ? []
          : ['inspector2:ListCoverage', 'inspector2:ListFindings'].map((action) => ({
              action,
              resource: '*',
              why: enhanced ? 'enhanced scanning: coverage and findings come from Inspector (account-level API)' : 'the registry scan type is unknown: ENHANCED scanning would need Inspector access',
              possible: enhanced === null
            })))
      ],
      forbidden: [
        { action: 'ssm:SendCommand', resource: a.instance, severity: 'FAIL', why: 'the push role must not reach the instance (push and deploy are separate roles)' },
        ...ECR_PUSH.map((action) => ({ action, resource: a.otherRepository, severity: 'FAIL', why: 'the push role may write only the configured repository' })),
        { action: 'iam:PassRole', resource: '*', severity: 'FAIL', why: 'a CI role must not pass roles' }
      ]
    };
  }
  if (role === 'deploy') {
    return {
      required: [
        { action: 'ssm:SendCommand', resource: a.instance, why: 'run the deploy on the configured instance' },
        { action: 'ssm:SendCommand', resource: a.runShellScript, why: 'SendCommand needs the document ARN as well' },
        { action: 'ssm:GetCommandInvocation', resource: '*', why: 'read the result (cannot be scoped to the instance)' }
      ],
      forbidden: [
        ...ECR_PUSH.map((action) => ({ action, resource: a.repository, severity: 'FAIL', why: 'the deploy role must not write images (push and deploy are separate roles)' })),
        { action: 'ssm:SendCommand', resource: a.otherInstance, severity: 'FAIL', why: 'the deploy role may reach only the configured instance' },
        { action: 'ssm:SendCommand', resource: a.otherDocument, severity: 'WARN', why: 'the deploy needs only AWS-RunShellScript' },
        { action: 'iam:PassRole', resource: '*', severity: 'FAIL', why: 'a CI role must not pass roles' }
      ]
    };
  }
  if (role === 'instance') {
    return {
      required: [
        { action: 'ecr:GetAuthorizationToken', resource: '*', why: 'the instance logs in to ECR to pull' },
        ...ECR_PULL.map((action) => ({ action, resource: a.repository, why: 'the instance pulls the approved digest' })),
        ...SSM_CORE.map((action) => ({ action, resource: '*', why: 'SSM managed-instance operation (AmazonSSMManagedInstanceCore)', soft: true }))
      ],
      forbidden: [...ECR_PUSH.map((action) => ({ action, resource: a.repository, severity: 'WARN', why: 'the instance only needs to pull' }))]
    };
  }
  throw new Error(`unknown role intent '${role}'`);
}

// [{ name, document }] -> statements with their policy name in the sid.
export function policyStatements(policies) {
  const out = [];
  const problems = [];
  for (const policy of policies) {
    try {
      out.push(...statements(policy.document).map((s) => ({ ...s, sid: `${policy.name}:${s.sid}` })));
    } catch (error) {
      problems.push({ severity: 'FAIL', kind: 'malformed-policy', message: `${policy.name}: ${error.message}` });
    }
  }
  return { statements: out, problems };
}

// Offline analysis. `policies` is every inline + attached policy of the role,
// `complete` false when any could not be read (then nothing is PASS).
// Returns { status, required[], findings[] }.
export function analyzePermissions(role, target, { policies, complete, enhanced = false, simulation = null }) {
  const req = roleRequirements(role, target, { enhanced });
  const { statements: stmts, problems } = policyStatements(policies);
  const findings = [...problems];
  const required = req.required.map((r) => {
    const g = grants(stmts, r.action, r.resource);
    const sim = simulation?.find((s) => s.action.toLowerCase() === r.action.toLowerCase() && s.resource === r.resource) ?? null;
    return { ...r, decision: g.decision, by: g.by, simulation: sim ? sim.decision : null };
  });
  for (const r of required) {
    if (r.decision === 'allowed') {
      if (r.simulation && r.simulation !== 'allowed') {
        findings.push({ severity: 'FAIL', kind: 'simulation-denies', message: `${r.action} on ${r.resource}: policy documents allow it but simulate-principal-policy says ${r.simulation} (a permissions boundary or SCP may deny it)` });
      }
      continue;
    }
    if (r.decision === 'conditional' || r.decision === 'unsupported') {
      // A possible grant is not proof: a required permission stays unproven.
      findings.push({
        severity: r.soft ? 'WARN' : 'NOT VERIFIED',
        kind: 'permission-unproven',
        message: `${r.action} on ${r.resource} (${r.why}): granted only conditionally, through NotAction/NotResource, or alongside an unevaluated statement (${r.by.join(', ')}), so it is not proven`
      });
      continue;
    }
    const severity = r.soft ? 'WARN' : r.possible ? 'NOT VERIFIED' : complete ? 'FAIL' : 'NOT VERIFIED';
    findings.push({ severity, kind: 'permission-missing', message: `${r.action} on ${r.resource} (${r.why}) is ${r.decision === 'denied' ? `explicitly denied by ${r.by.join(', ')}` : 'not granted by the role\'s policies'}` });
  }
  for (const f of req.forbidden) {
    const g = grants(stmts, f.action, f.resource);
    if (g.decision === 'allowed' || g.decision === 'conditional' || g.decision === 'unsupported') {
      // A forbidden permission that MAY be granted is as serious as one that is.
      findings.push({ severity: f.severity, kind: 'permission-too-broad', message: `${f.action} on ${f.resource} is ${g.decision === 'allowed' ? 'granted' : `possibly granted (${g.decision})`} by ${g.by.join(', ')}: ${f.why}` });
    }
  }
  const admin = stmts.filter((s) => s.effect === 'Allow' && s.actions.includes('*') && s.resources.includes('*'));
  if (admin.length > 0) {
    findings.push({ severity: 'FAIL', kind: 'administrator', message: `Action "*" on Resource "*" is granted by ${admin.map((s) => s.sid).join(', ')}` });
  }
  // Allow + NotAction over every resource is "everything except a list": treat
  // it as possible administrator access.
  const possibleAdmin = stmts.filter((s) => s.effect === 'Allow' && s.notActions.length > 0 && (s.resources.includes('*') || s.notResources.length > 0));
  if (possibleAdmin.length > 0) {
    findings.push({ severity: 'FAIL', kind: 'possible-administrator', message: `Allow with NotAction on every resource ("everything except …") is granted by ${possibleAdmin.map((s) => s.sid).join(', ')}` });
  }
  if (!complete) {
    findings.push({ severity: 'NOT VERIFIED', kind: 'policies-incomplete', message: 'not every policy of the role could be read, so the analysis is incomplete' });
  }
  const status = findings.some((f) => f.severity === 'FAIL')
    ? 'FAIL'
    : findings.some((f) => f.severity === 'NOT VERIFIED')
      ? 'NOT VERIFIED'
      : findings.some((f) => f.severity === 'WARN')
        ? 'WARN'
        : 'PASS';
  return { status, required, findings };
}

// Groups of required actions per resource, for simulate-principal-policy.
export function simulationGroups(role, target, { enhanced = false } = {}) {
  // Only what is certainly required; possibly-needed actions are not simulated.
  const groups = new Map();
  for (const r of roleRequirements(role, target, { enhanced: enhanced === true }).required) {
    if (!groups.has(r.resource)) {
      groups.set(r.resource, []);
    }
    groups.get(r.resource).push(r.action);
  }
  return [...groups].map(([resource, actions]) => ({ resource, actions }));
}

// A least-privilege statement set for the instance role, printed as a
// RECOMMENDATION when it is missing permissions. Never attached by the tool.
export function proposedInstancePolicy(target) {
  const a = arns(target);
  return {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'EcrLogin', Effect: 'Allow', Action: 'ecr:GetAuthorizationToken', Resource: '*' },
      { Sid: 'PullApprovedImages', Effect: 'Allow', Action: ECR_PULL, Resource: a.repository }
    ]
  };
}

// --- builder (Phase 2B) --------------------------------------------------------------

// Readable statement ids for the resources roleRequirements() names.
const SID_BY_ARN_KEY = { repository: 'ConfiguredRepository', instance: 'ConfiguredInstance', runShellScript: 'RunShellScriptDocument' };

// The identity policy ssd-onboard generates for a delivery role, built from
// roleRequirements().required — the SAME list `aws doctor` checks a role
// against, so there is no second definition of what the role may do. One
// statement per resource, in requirement order. `enhanced` must be decided
// (true/false): a possibly-needed permission is never generated.
// The document must PASS analyzePermissions() (sufficient AND not too broad)
// or nothing is generated.
export function rolePolicyDocument(role, target, { enhanced }) {
  if (role !== 'push' && role !== 'deploy') {
    throw new Error(`no generated policy for role intent '${role}'`);
  }
  if (enhanced !== true && enhanced !== false) {
    throw new Error('rolePolicyDocument: the registry scan type must be known (BASIC or ENHANCED)');
  }
  const a = arns(target);
  const byResource = new Map();
  for (const r of roleRequirements(role, target, { enhanced }).required) {
    if (!byResource.has(r.resource)) {
      byResource.set(r.resource, []);
    }
    if (!byResource.get(r.resource).includes(r.action)) {
      byResource.get(r.resource).push(r.action);
    }
  }
  const sidOf = (resource) => (resource === '*' ? 'AccountLevel' : SID_BY_ARN_KEY[Object.keys(SID_BY_ARN_KEY).find((key) => a[key] === resource)] ?? null);
  const document = {
    Version: '2012-10-17',
    Statement: [...byResource].map(([resource, actions]) => {
      const sid = sidOf(resource);
      if (!sid) {
        throw new Error(`no statement id for resource ${resource}`);
      }
      return { Sid: sid, Effect: 'Allow', Action: actions, Resource: resource };
    })
  };
  const analysis = analyzePermissions(role, target, { policies: [{ name: 'generated', document }], complete: true, enhanced });
  if (analysis.status !== 'PASS') {
    throw new Error(`the generated ${role} policy does not pass the permission analysis: ${analysis.findings.map((f) => `${f.severity} ${f.kind}: ${f.message}`).join('; ')}`);
  }
  return document;
}
