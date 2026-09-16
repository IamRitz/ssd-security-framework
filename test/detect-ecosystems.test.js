import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { detectEcosystems } from '../security/scripts/detect-ecosystems.mjs';

async function repoWith(files) {
  const dir = await mkdtemp(join(tmpdir(), 'detect-eco-'));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content);
  }
  return dir;
}

describe('detectEcosystems', () => {
  it('detects an npm-only repo', async () => {
    const dir = await repoWith({ 'package-lock.json': '{}' });
    try {
      const result = await detectEcosystems(dir);
      assert.equal(result.npm, true);
      assert.equal(result.python, false);
      assert.equal(result.npmMarker, 'package-lock.json');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('detects a Python-only repo (requirements.txt) and exposes the pip-audit target', async () => {
    const dir = await repoWith({ 'requirements.txt': 'requests==2.19.1\n' });
    try {
      const result = await detectEcosystems(dir);
      assert.equal(result.npm, false);
      assert.equal(result.python, true);
      assert.equal(result.requirementsTxt, 'requirements.txt');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('detects a Python project via poetry.lock even without requirements.txt', async () => {
    const dir = await repoWith({ 'pyproject.toml': '[tool.poetry]\n', 'poetry.lock': '' });
    try {
      const result = await detectEcosystems(dir);
      assert.equal(result.python, true);
      assert.equal(result.requirementsTxt, null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('detects a monorepo with both ecosystems', async () => {
    const dir = await repoWith({ 'package.json': '{}', 'requirements.txt': '' });
    try {
      const result = await detectEcosystems(dir);
      assert.equal(result.npm, true);
      assert.equal(result.python, true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reports neither for a repo with no dependency manifests', async () => {
    const dir = await repoWith({ 'README.md': '# hi' });
    try {
      const result = await detectEcosystems(dir);
      assert.equal(result.npm, false);
      assert.equal(result.python, false);
      assert.equal(result.npmMarker, null);
      assert.equal(result.pythonMarker, null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
