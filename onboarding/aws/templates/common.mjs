// Shared pieces of every CloudFormation template ssd-onboard renders.
//
// DETERMINISM. A template is a pure function of the configuration, the
// partition and the observed registry scan type: no timestamp, random value,
// hostname, user name or caller ARN is ever an input. Templates are JSON (a
// YAML file could not hold the policies built by policy/trust.mjs and
// policy/permissions.mjs without a second definition of them), serialized by
// canonicalJson(): object keys sorted, two-space indentation, one trailing
// newline. Same inputs + same framework commit -> byte-identical template.
import { createHash } from 'node:crypto';

import { SSD_TAGS } from '../discover/stacks.mjs';
import { DELIVERY_ENVIRONMENT, canonicalSlug } from '../stack-names.mjs';

export const TEMPLATE_FORMAT_VERSION = '2010-09-09';

// Objects with sorted keys, recursively; arrays keep their order (it can be
// meaningful, e.g. policy statements).
export function sortKeys(value) {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortKeys(value[key])])
    );
  }
  return value;
}

export const canonicalJson = (value) => `${JSON.stringify(sortKeys(value), null, 2)}\n`;
export const sha256 = (text) => createHash('sha256').update(text).digest('hex');

// The ownership tags, as CloudFormation's [{ Key, Value }], sorted by key.
// Every managed stack and resource carries them; per-repository ones also name
// the canonical consumer repository.
export function ssdTags({ scope, slug }) {
  const tags = [
    { Key: SSD_TAGS.framework[0], Value: SSD_TAGS.framework[1] },
    { Key: SSD_TAGS.managedBy[0], Value: SSD_TAGS.managedBy[1] },
    { Key: SSD_TAGS.environment, Value: DELIVERY_ENVIRONMENT },
    ...(scope === 'repo' ? [{ Key: SSD_TAGS.consumer, Value: canonicalSlug(slug) }] : [])
  ];
  return tags.sort((a, b) => (a.Key < b.Key ? -1 : a.Key > b.Key ? 1 : 0));
}

// Every managed resource is RETAINED: removing it from the template, deleting
// the stack, or a replacement never deletes the underlying resource. Such a
// change is still classified (DELETE / REPLACE) and surfaced by the plan.
export const retained = (type, properties) => ({ Type: type, DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain', Properties: properties });

export function template(description, resources) {
  return { AWSTemplateFormatVersion: TEMPLATE_FORMAT_VERSION, Description: description, Resources: resources };
}
