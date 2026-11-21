import { Body, SetMetadata } from '@nestjs/common';
import type { z } from 'zod';

import { IS_PUBLIC_KEY, Public } from '../../common/auth/public.decorator.js';
import { ZodValidationPipe } from '../../common/pipes/zod-validation.pipe.js';
import type { PermissionName } from './permissions.js';

/**
 * Access markers (ADR-008 Z3). Every route handler carries EXACTLY one of
 * `@Public()`, `@SelfService()` or `@RequirePermission(p)`. Markers are
 * handler-level only: a class-level marker is rejected by the boot scan and
 * the route-scan test, and the runtime guard fails closed with a generic 403.
 *
 * `@Public()` itself stays in `common/auth` (the authentication guard owns the
 * "no token" decision); this module re-exports it so the scan and controllers
 * have one import for all three markers.
 */

export { IS_PUBLIC_KEY, Public };

export const IS_SELF_SERVICE_KEY = 'authz:self-service';
export const REQUIRE_PERMISSION_KEY = 'authz:require-permission';

/** The body schema recorded on the handler for the route scan (SA-05). */
export const BODY_SCHEMA_KEY = 'authz:body-schema';

/** Any authenticated principal, acting only on its own identity (e.g. /auth/me). */
export const SelfService = (): MethodDecorator => SetMetadata(IS_SELF_SERVICE_KEY, true);

/** The principal must hold exactly this catalog permission. */
export const RequirePermission = (permission: PermissionName): MethodDecorator =>
  SetMetadata(REQUIRE_PERMISSION_KEY, permission);

/**
 * `@Body(new ZodValidationPipe(schema))` plus handler metadata. The sensitive
 * route scan reads the schema because guards run before pipes (ADR-008 Z10,
 * CP1 SA-05): it must prove the body really validates `reason`.
 */
export function ZodBody<T extends z.ZodType>(schema: T): ParameterDecorator {
  return (target: object, propertyKey: string | symbol | undefined, parameterIndex: number) => {
    if (propertyKey !== undefined) {
      const handler = (target as Record<PropertyKey, unknown>)[propertyKey];
      if (typeof handler === 'function') {
        Reflect.defineMetadata(BODY_SCHEMA_KEY, schema, handler);
      }
    }
    Body(new ZodValidationPipe(schema))(target, propertyKey, parameterIndex);
  };
}

/** True when the class itself carries any access marker (always invalid). */
export function hasClassLevelAccessMarker(target: object): boolean {
  return [IS_PUBLIC_KEY, IS_SELF_SERVICE_KEY, REQUIRE_PERMISSION_KEY].some(
    (key) => Reflect.getMetadata(key, target) !== undefined,
  );
}
