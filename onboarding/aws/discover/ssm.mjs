// The configured deploy target: an EXISTING EC2 instance managed by SSM.
// Phase 2 never creates it and never changes its instance profile.
import { absent, present, read } from './result.mjs';

// -> result whose value is { pingStatus, resourceType, platform, agentVersion }
export async function discoverManagedInstance(aws, { instanceId }) {
  const filters = JSON.stringify([{ Key: 'InstanceIds', Values: [instanceId] }]);
  const got = await read(aws, ['ssm', 'describe-instance-information', '--filters', filters]);
  if (got.state !== 'present') {
    return got;
  }
  const info = (Array.isArray(got.value.InstanceInformationList) ? got.value.InstanceInformationList : []).find((i) => i?.InstanceId === instanceId);
  if (!info) {
    return absent('NotManaged');
  }
  return present({ pingStatus: info.PingStatus ?? null, resourceType: info.ResourceType ?? null, platform: info.PlatformName ?? null, agentVersion: info.AgentVersion ?? null });
}

// -> result whose value is { ownerId, state, instanceProfileArn }
export async function discoverInstance(aws, { instanceId }) {
  const got = await read(aws, ['ec2', 'describe-instances', '--instance-ids', instanceId], { notFound: ['InvalidInstanceID.NotFound'] });
  if (got.state !== 'present') {
    return got;
  }
  for (const reservation of Array.isArray(got.value.Reservations) ? got.value.Reservations : []) {
    const instance = (Array.isArray(reservation?.Instances) ? reservation.Instances : []).find((i) => i?.InstanceId === instanceId);
    if (instance) {
      return present({ ownerId: reservation.OwnerId ?? null, state: instance.State?.Name ?? null, instanceProfileArn: instance.IamInstanceProfile?.Arn ?? null });
    }
  }
  return absent('NotReturned');
}

// -> result whose value is { arn, roles: [arn] }
export async function discoverInstanceProfile(aws, arn) {
  const name = arn.split('/').pop();
  const got = await read(aws, ['iam', 'get-instance-profile', '--instance-profile-name', name], { notFound: ['NoSuchEntity'] });
  if (got.state !== 'present') {
    return got;
  }
  const profile = got.value.InstanceProfile ?? {};
  return present({ arn: profile.Arn ?? null, roles: (Array.isArray(profile.Roles) ? profile.Roles : []).map((r) => String(r?.Arn ?? '')).filter(Boolean) });
}
