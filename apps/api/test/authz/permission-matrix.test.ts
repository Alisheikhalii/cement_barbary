import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import type { INestApplication } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { extractMatrixBlock, renderMatrix } from '../../src/security/authz/matrix.js';
import { scanRoutes } from '../../src/security/authz/route-scan.js';
import { buildMatrixApp, collectProductionRoutes } from './matrix-harness.js';

/**
 * Matrix sync (F1-05 T07). The committed generated block must equal what the
 * catalog + role map + real route scan produce right now. This is the same
 * data the BFLA suite iterates; drift fails CI.
 */
const DOCUMENT = fileURLToPath(
  new URL('../../../../docs/security/permission-matrix.md', import.meta.url),
);

let app: INestApplication;

beforeAll(async () => {
  app = await buildMatrixApp();
}, 60000);

afterAll(async () => {
  await app?.close();
});

describe('permission matrix sync', () => {
  it('matches the committed generated block', async () => {
    const markdown = await readFile(DOCUMENT, 'utf8');
    const routes = collectProductionRoutes(app);
    expect(extractMatrixBlock(markdown)).toBe(renderMatrix(routes).trim());
  });

  it('renders a row for every catalog permission and production route', async () => {
    const generated = renderMatrix(collectProductionRoutes(app));
    for (const permission of [
      'destination.read',
      'destination.write',
      'hall.read',
      'hall.write',
      'loader_type.read',
      'loader_type.write',
      'carrier.read',
      'carrier.write',
      'carrier_membership.write',
      'carrier_quota.write',
    ]) {
      expect(generated).toContain(`\`${permission}\``);
    }
    for (const route of collectProductionRoutes(app)) {
      expect(generated).toContain(`\`${route.path}\``);
    }
  });

  it('fails the route scan if a production route drifts from the reviewed surface', () => {
    const routes = collectProductionRoutes(app);
    // The real surface is clean today. Production mode additionally exercises
    // the controller/module allowlist and canonical public-path rules; the
    // boot check runs the same functions before the app accepts traffic.
    expect(scanRoutes(routes, 'test')).toEqual([]);
    expect(scanRoutes(routes, 'production')).toEqual([]);
  });
});
