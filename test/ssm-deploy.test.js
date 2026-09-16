import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  buildImage,
  buildDeployCommands,
  buildSendParameters,
  sendCommandArgs,
  getInvocationArgs
} from '../security/scripts/ssm-deploy.mjs';

const options = {
  instance_id: 'i-0123456789abcdef0',
  region: 'us-east-1',
  registry: '157328692276.dkr.ecr.us-east-1.amazonaws.com',
  repository: 'secure-software-delivery',
  image_tag: 'abc123',
  container_name: 'secure-software-delivery',
  app_port: '3000'
};

describe('ssm-deploy command building', () => {
  it('builds the fully-qualified image reference', () => {
    assert.equal(
      buildImage(options),
      '157328692276.dkr.ecr.us-east-1.amazonaws.com/secure-software-delivery:abc123'
    );
  });

  it('deploys by immutable digest when one is supplied (preferred over tag)', () => {
    assert.equal(
      buildImage({ ...options, image_digest: 'sha256:deadbeef' }),
      '157328692276.dkr.ecr.us-east-1.amazonaws.com/secure-software-delivery@sha256:deadbeef'
    );
  });

  it('produces a fail-fast docker login/pull/run remote command', () => {
    const commands = buildDeployCommands(options);
    assert.equal(commands[0], 'set -e');
    assert.match(commands[1], /aws ecr get-login-password --region us-east-1 \| docker login/);
    assert.match(commands[2], /^docker pull .*secure-software-delivery:abc123$/);
    assert.match(commands[3], /docker rm -f secure-software-delivery/);
    assert.match(commands[4], /docker run -d --name secure-software-delivery .* -p 3000:3000 /);
    assert.ok(commands.includes('docker image prune -f'));
  });

  it('honors a custom container name and app port', () => {
    const commands = buildDeployCommands({ ...options, container_name: 'app', app_port: '8080' });
    assert.match(commands[3], /docker rm -f app/);
    assert.match(commands[4], /-p 8080:3000/);
  });

  it('serializes the SSM parameters as a valid AWS-RunShellScript document', () => {
    const parsed = JSON.parse(buildSendParameters(options));
    assert.deepEqual(parsed.executionTimeout, ['600']);
    assert.equal(parsed.commands[0], 'set -e');
    assert.equal(parsed.commands.length, 6);
  });

  it('targets the instance id (plural for send, singular for get)', () => {
    const send = sendCommandArgs(options);
    assert.ok(send.includes('--instance-ids'));
    assert.equal(send[send.indexOf('--instance-ids') + 1], 'i-0123456789abcdef0');
    assert.equal(send[send.indexOf('--document-name') + 1], 'AWS-RunShellScript');

    const get = getInvocationArgs(options, 'cmd-1');
    assert.ok(get.includes('--instance-id'));
    assert.equal(get[get.indexOf('--command-id') + 1], 'cmd-1');
  });
});
