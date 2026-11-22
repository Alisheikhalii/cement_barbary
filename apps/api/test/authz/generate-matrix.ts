import 'reflect-metadata';

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { MetadataScanner } from '@nestjs/core';

import { AuthController } from '../../src/modules/auth/auth.controller.js';
import { HealthController } from '../../src/modules/health/health.controller.js';
import { renderMatrix, replaceMatrixBlock } from '../../src/security/authz/matrix.js';
import {
  collectRoutesFromSources,
  type ControllerRouteSource,
} from '../../src/security/authz/route-discovery.js';
import { PRODUCTION_CONTROLLERS } from '../../src/security/authz/route-scan.js';

/**
 * `pnpm --filter @bitabar/api authz:matrix` (F1-05 T07).
 *
 * Regenerates ONLY the marked block in docs/security/permission-matrix.md from
 * the permission catalog, the role map and the real production route metadata.
 * It reads decorators directly (no Nest container), so it runs under `tsx`
 * without decorator-metadata emission. The sync test boots the real app and
 * compares the same block, so a controller missing from this list fails CI.
 */
const DOCUMENT = fileURLToPath(
  new URL('../../../../docs/security/permission-matrix.md', import.meta.url),
);

const PRODUCTION_CLASSES: readonly ControllerRouteSource[] = [
  { metatype: HealthController, instance: null, moduleName: 'HealthModule' },
  { metatype: AuthController, instance: null, moduleName: 'AuthModule' },
];

function productionRoutes() {
  const names = PRODUCTION_CLASSES.map((source) => source.metatype.name);
  for (const expected of PRODUCTION_CONTROLLERS) {
    if (!names.includes(expected)) {
      throw new Error(`production controller ${expected} is missing from the matrix script`);
    }
  }
  return collectRoutesFromSources(PRODUCTION_CLASSES, new MetadataScanner()).filter((route) =>
    (PRODUCTION_CONTROLLERS as readonly string[]).includes(route.controllerName),
  );
}

async function main(): Promise<void> {
  const current = await readFile(DOCUMENT, 'utf8');
  const next = replaceMatrixBlock(current, renderMatrix(productionRoutes()));
  if (next === current) {
    process.stdout.write('permission matrix is current\n');
    return;
  }
  await writeFile(DOCUMENT, next, 'utf8');
  process.stdout.write(`updated ${DOCUMENT}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : 'matrix generation failed'}\n`);
  process.exitCode = 1;
});
