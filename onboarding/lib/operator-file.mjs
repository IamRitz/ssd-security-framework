// Reads the Phase 3 break-glass OPERATOR configuration file named by
// --operator-config (onboarding/aws/break-glass/operator-config.mjs validates
// it). Only `ssd-onboard aws … --operator-config` reaches this module; no
// Phase 1 command imports it, so Phase 1 never reads the file.
import { readFile } from 'node:fs/promises';

import { OperatorConfigError, parseOperatorConfig } from '../aws/break-glass/operator-config.mjs';

export async function loadOperatorConfig(path) {
  let source;
  try {
    source = await readFile(path, 'utf8');
  } catch (error) {
    throw new OperatorConfigError([`cannot read ${path}: ${error.code ?? error.message}`]);
  }
  return parseOperatorConfig(source);
}
