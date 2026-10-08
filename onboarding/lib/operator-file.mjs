// Reads the Phase 3 break-glass OPERATOR configuration file named by
// --operator-config (onboarding/aws/break-glass/operator-config.mjs validates
// it). Only `ssd-onboard aws … --operator-config` reaches this module; no
// Phase 1 command imports it, so Phase 1 never reads the file.
import { readFile } from 'node:fs/promises';

import { FrameworkPolicyConfigError, parseFrameworkPolicyConfig } from '../aws/break-glass/framework-policy-config.mjs';
import { OperatorConfigError, parseOperatorConfig } from '../aws/break-glass/operator-config.mjs';
import { RepositoryConfigError, parseRepositoryConfig } from '../aws/break-glass/repository-config.mjs';

export async function loadOperatorConfig(path) {
  let source;
  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    throw new OperatorConfigError([`cannot read ${path}: ${error.code ?? error.message}`]);
  }
  return parseOperatorConfig(source);
}

// Phase 3D: the framework policy file named by --policy-config
// (onboarding/aws/break-glass/framework-policy-config.mjs). `environment` is
// --environment when the command names one; the file must agree.
export async function loadFrameworkPolicyConfig(path, { environment } = {}) {
  let source;
  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    throw new FrameworkPolicyConfigError([`cannot read ${path}: ${error.code ?? error.message}`]);
  }
  return parseFrameworkPolicyConfig(source, { environment });
}

// Phase 3D: the repository file named by --repository-config
// (onboarding/aws/break-glass/repository-config.mjs).
export async function loadRepositoryConfig(path) {
  let source;
  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    throw new RepositoryConfigError([`cannot read ${path}: ${error.code ?? error.message}`]);
  }
  return parseRepositoryConfig(source);
}
