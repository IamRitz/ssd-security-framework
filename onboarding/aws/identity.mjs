// Who is calling AWS, in which account and region — decided before any other
// AWS call is made.
//
//   region   --region flag > delivery.aws.region > refuse. Never the AWS CLI's
//            implicit default: the wrapper appends the resolved region to every
//            call. A flag that disagrees with the configured region blocks.
//   caller   `sts get-caller-identity`. The account must equal
//            delivery.aws.accountId, the ARN must name that same account, and
//            the account root user is refused outright.
const ACCOUNT = /^\d{12}$/;
export const REGION = /^[a-z]{2}(?:-[a-z]+)+-\d$/;
// arn:<partition>:<service>::<account>:<resource>
const PRINCIPAL_ARN = /^arn:(aws|aws-cn|aws-us-gov):(iam|sts)::(\d{12}):(.+)$/;

export class IdentityError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'IdentityError';
    this.kind = kind;
  }
}

// { explicit, configured } -> { region, source, configured } | throws.
// `explicit` wins as the value; a disagreeing configured value is reported by
// regionCheck, never silently overridden.
export function resolveRegion({ explicit = null, configured = null } = {}) {
  if (explicit !== null && explicit !== undefined) {
    if (!REGION.test(explicit)) {
      throw new IdentityError('configuration', `--region '${explicit}' is not an AWS region name`);
    }
    return { region: explicit, source: 'flag', configured: configured ?? null };
  }
  if (configured) {
    return { region: configured, source: 'config', configured };
  }
  throw new IdentityError('region-missing', 'no region: pass --region or set delivery.aws.region (the AWS CLI default region is never used)');
}

// The principal kind an ARN names. `root` is the account root user.
export function principalKind(arn) {
  const match = PRINCIPAL_ARN.exec(arn ?? '');
  if (!match) {
    return null;
  }
  const [, , service, , resource] = match;
  if (service === 'iam' && resource === 'root') {
    return 'root';
  }
  if (service === 'sts' && resource.startsWith('assumed-role/')) {
    return 'assumed-role';
  }
  if (service === 'sts' && resource.startsWith('federated-user/')) {
    return 'federated-user';
  }
  if (service === 'iam' && resource.startsWith('user/')) {
    return 'user';
  }
  return 'other';
}

// `sts get-caller-identity` JSON -> { account, arn, userId, kind } | throws.
export function parseCallerIdentity(json) {
  const account = json?.Account;
  const arn = json?.Arn;
  const userId = json?.UserId;
  if (typeof account !== 'string' || !ACCOUNT.test(account) || typeof arn !== 'string' || typeof userId !== 'string') {
    throw new IdentityError('malformed', 'sts get-caller-identity returned an unexpected document');
  }
  const match = PRINCIPAL_ARN.exec(arn);
  if (!match) {
    throw new IdentityError('malformed', 'sts get-caller-identity returned an ARN that is not an IAM/STS principal');
  }
  if (match[3] !== account) {
    throw new IdentityError('malformed', `the caller ARN names account ${match[3]}, but Account is ${account}`);
  }
  return { account, arn, userId, kind: principalKind(arn), partition: match[1] };
}

export async function callerIdentity(aws) {
  return parseCallerIdentity(await aws(['sts', 'get-caller-identity']));
}

// --- checks (pure) ------------------------------------------------------------------

export function accountCheck(caller, expectedAccount) {
  const ok = caller.account === expectedAccount;
  return {
    id: 'identity.account',
    section: 'Identity',
    title: 'Caller account',
    status: ok ? 'PASS' : 'FAIL',
    required: true,
    basis: 'runtime',
    observed: [`caller account ${caller.account}`],
    expected: [`delivery.aws.accountId ${expectedAccount}`],
    findings: ok ? [] : [{ kind: 'account-mismatch', message: `authenticated to account ${caller.account}, but the configuration is for ${expectedAccount}` }],
    remediation: ok ? [] : ['Authenticate to the configured account (e.g. choose the right AWS_PROFILE), or correct delivery.aws.accountId.']
  };
}

export function principalCheck(caller) {
  const root = caller.kind === 'root';
  return {
    id: 'identity.principal',
    section: 'Identity',
    title: 'Caller principal',
    status: root ? 'FAIL' : 'PASS',
    required: true,
    basis: 'runtime',
    observed: [`${caller.arn} (${caller.kind})`],
    expected: ['an IAM user or assumed role — never the account root user'],
    findings: root ? [{ kind: 'root-principal', message: 'the caller is the AWS account root user' }] : [],
    remediation: root ? ['Use a least-privilege IAM identity or an assumed role (docs/aws-setup.md § Local operator identity).'] : []
  };
}

export function regionCheck(resolved) {
  const mismatch = resolved.source === 'flag' && resolved.configured && resolved.configured !== resolved.region;
  return {
    id: 'identity.region',
    section: 'Identity',
    title: 'Region',
    status: mismatch ? 'FAIL' : 'PASS',
    required: true,
    basis: 'configuration',
    observed: [`${resolved.region} (from ${resolved.source === 'flag' ? '--region' : 'delivery.aws.region'})`],
    expected: [resolved.configured ? `delivery.aws.region ${resolved.configured}` : 'an explicit region'],
    findings: mismatch ? [{ kind: 'region-mismatch', message: `--region ${resolved.region} differs from delivery.aws.region ${resolved.configured}` }] : [],
    remediation: mismatch ? ['Omit --region, or pass the configured region; to move regions, change delivery.aws.region deliberately.'] : []
  };
}
