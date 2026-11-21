import { Inject, Injectable } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants.js';
import { DiscoveryService, MetadataScanner } from '@nestjs/core';

import {
  BODY_SCHEMA_KEY,
  hasClassLevelAccessMarker,
  IS_PUBLIC_KEY,
  IS_SELF_SERVICE_KEY,
  REQUIRE_PERMISSION_KEY,
} from './decorators.js';
import {
  canonicalRoutePath,
  normalizeRoutePaths,
  type ScannedController,
  type ScannedRoute,
} from './route-scan.js';

/** Controllers excluded from the global API prefix in `main.ts`. */
const UNPREFIXED_CONTROLLER_PATHS = new Set(['health']);

/** RequestMethod numeric enum order (GET = 0, POST = 1, …). */
const REQUEST_METHOD_NAMES = [
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'ALL',
  'OPTIONS',
  'HEAD',
  'SEARCH',
] as const;

/**
 * Reads the real Nest controller/route metadata once (ADR-008 Z3). Used by the
 * boot assertion and available to the route-scan test; it never mutates the
 * container and never touches HTTP or the database.
 */
@Injectable()
export class AuthzRouteDiscovery {
  constructor(
    @Inject(DiscoveryService) private readonly discovery: DiscoveryService,
    @Inject(MetadataScanner) private readonly metadataScanner: MetadataScanner,
  ) {}

  collect(): readonly ScannedRoute[] {
    const routes: ScannedRoute[] = [];
    for (const wrapper of this.discovery.getControllers()) {
      const instance: unknown = wrapper.instance;
      const metatype: unknown = wrapper.metatype;
      if (typeof metatype !== 'function') {
        continue;
      }
      const controllerPaths = normalizeRoutePaths(Reflect.getMetadata(PATH_METADATA, metatype));
      const classLevelMarker = hasClassLevelAccessMarker(metatype);
      const controllerName = metatype.name;
      const moduleName = this.moduleNameOf(wrapper);
      // Request-scoped controllers have no pre-built instance; their route
      // metadata still lives on the class prototype, so scan it instead of
      // letting the controller become invisible (reviewer finding 4).
      const instanceObject =
        instance !== null && instance !== undefined && typeof instance === 'object'
          ? instance
          : null;
      const prototype = instanceObject
        ? (Object.getPrototypeOf(instanceObject) as object | null)
        : ((metatype as { prototype?: object }).prototype ?? null);
      if (prototype === null) {
        continue;
      }
      const methodSource = (instanceObject ?? prototype) as Record<string, unknown>;
      for (const methodName of this.metadataScanner.getAllMethodNames(prototype)) {
        const handler: unknown = methodSource[methodName];
        if (typeof handler !== 'function') {
          continue;
        }
        const requestMethod: unknown = Reflect.getMetadata(METHOD_METADATA, handler);
        if (typeof requestMethod !== 'number') {
          // Not a route handler (a helper method on the controller).
          continue;
        }
        const handlerPaths = normalizeRoutePaths(Reflect.getMetadata(PATH_METADATA, handler));
        const isPublic = Reflect.getMetadata(IS_PUBLIC_KEY, handler) === true;
        const isSelfService = Reflect.getMetadata(IS_SELF_SERVICE_KEY, handler) === true;
        const permissionMetadata: unknown = Reflect.getMetadata(REQUIRE_PERMISSION_KEY, handler);
        const isPermission = permissionMetadata !== undefined;
        const bodySchema: unknown = Reflect.getMetadata(BODY_SCHEMA_KEY, handler);
        for (const controllerPath of controllerPaths) {
          for (const handlerPath of handlerPaths) {
            routes.push({
              moduleName,
              controllerName,
              handlerName: methodName,
              method: this.methodName(requestMethod),
              path: canonicalRoutePath(
                controllerPath,
                handlerPath,
                UNPREFIXED_CONTROLLER_PATHS.has(controllerPath),
              ),
              isPublic,
              isSelfService,
              isPermission,
              classLevelMarker,
              permission: typeof permissionMetadata === 'string' ? permissionMetadata : null,
              bodySchema: bodySchema ?? null,
            });
          }
        }
      }
    }
    return routes;
  }

  /** Every controller, including one with no route handlers (RD-03). */
  collectControllers(): readonly ScannedController[] {
    const controllers: ScannedController[] = [];
    for (const wrapper of this.discovery.getControllers()) {
      const metatype: unknown = wrapper.metatype;
      if (typeof metatype !== 'function') {
        continue;
      }
      controllers.push({
        moduleName: this.moduleNameOf(wrapper),
        controllerName: metatype.name,
      });
    }
    return controllers;
  }

  private moduleNameOf(wrapper: object): string {
    const host = (wrapper as { host?: { metatype?: { name?: unknown } } | null }).host;
    const name = host?.metatype?.name;
    return typeof name === 'string' && name.length > 0 ? name : 'UnknownModule';
  }

  private methodName(value: number): string {
    return REQUEST_METHOD_NAMES[value] ?? `METHOD_${value}`;
  }
}
