import { Controller, Delete, Get, HttpCode, Inject, Patch, Post, Req } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';

import { Idempotent } from '../../../common/idempotency/idempotent.decorator.js';
import {
  RequirePermission,
  ZodBody,
  ZodParams,
  ZodQuery,
} from '../../../security/authz/decorators.js';
import { readAuthzContext } from '../../../security/authz/access-scope.js';
import { DestinationsService, type DestinationWriteActor } from './destinations.service.js';
import {
  createDestinationSchema,
  deleteDestinationQuerySchema,
  destinationIdParamsSchema,
  destinationListQuerySchema,
  emptyQuerySchema,
  updateDestinationSchema,
  type CreateDestinationInput,
  type DeleteDestinationQuery,
  type DestinationListQuery,
  type DestinationListResult,
  type UpdateDestinationInput,
} from './destinations.schemas.js';
import type { DestinationDto } from './destinations.types.js';

/**
 * Destination CRUD (F1-07 T04, ADR-011 B1). The path and permissions are the
 * reviewed surface: `destination.read` for reads, `destination.write` for the
 * three mutations, each mutation idempotent (ADR-010 L10).
 *
 * The controller never reads `tenantId`, `nameKey` or `version` from input:
 * the scope comes from the guard and the version from `expectedVersion`.
 */
@ApiTags('base-data')
@Controller('base/destinations')
export class DestinationsController {
  constructor(@Inject(DestinationsService) private readonly destinations: DestinationsService) {}

  @RequirePermission('destination.read')
  @Get()
  @ApiOperation({ summary: 'List live destinations (paged, filtered, sorted)' })
  async list(
    @ZodQuery(destinationListQuerySchema) query: DestinationListQuery,
    @Req() request: Request,
  ): Promise<DestinationListResult> {
    return this.destinations.list(readAuthzContext(request).scope, query);
  }

  @RequirePermission('destination.read')
  @Get(':id')
  @ApiOperation({ summary: 'Read one live destination' })
  async get(
    @ZodParams(destinationIdParamsSchema) params: { id: string },
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<DestinationDto> {
    return this.destinations.get(readAuthzContext(request).scope, params.id);
  }

  @RequirePermission('destination.write')
  @Idempotent()
  @Post()
  @ApiOperation({ summary: 'Create a destination' })
  async create(
    @ZodBody(createDestinationSchema) body: CreateDestinationInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<DestinationDto> {
    return this.destinations.create(readAuthzContext(request).scope, body, this.actor(request));
  }

  @RequirePermission('destination.write')
  @Idempotent()
  @Patch(':id')
  @ApiOperation({ summary: 'Update a destination (optimistic concurrency)' })
  async update(
    @ZodParams(destinationIdParamsSchema) params: { id: string },
    @ZodBody(updateDestinationSchema) body: UpdateDestinationInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<DestinationDto> {
    return this.destinations.update(
      readAuthzContext(request).scope,
      params.id,
      body,
      this.actor(request),
    );
  }

  @RequirePermission('destination.write')
  @Idempotent()
  @Delete(':id')
  @HttpCode(204)
  @ApiOperation({ summary: 'Soft-delete a destination' })
  async remove(
    @ZodParams(destinationIdParamsSchema) params: { id: string },
    @ZodQuery(deleteDestinationQuerySchema) query: DeleteDestinationQuery,
    @Req() request: Request,
  ): Promise<void> {
    return this.destinations.delete(
      readAuthzContext(request).scope,
      params.id,
      query,
      this.actor(request),
    );
  }

  /** Audit actor from the verified principal + request metadata. */
  private actor(request: Request): DestinationWriteActor {
    const { principal } = readAuthzContext(request);
    const id = (request as Request & { id?: unknown }).id;
    return {
      userId: principal.userId,
      sessionId: principal.sessionId,
      ip: typeof request.ip === 'string' && request.ip.length > 0 ? request.ip : null,
      requestId: typeof id === 'string' && id.length > 0 ? id : null,
    };
  }
}
