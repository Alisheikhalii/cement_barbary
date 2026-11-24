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
import { writeActor } from '../base-data.actor.js';
import { LoaderTypesService } from './loader-types.service.js';
import {
  createLoaderTypeGroupSchema,
  deleteQuerySchema,
  emptyQuerySchema,
  loaderTypeGroupListQuerySchema,
  loaderTypeGroupParamsSchema,
  updateLoaderTypeGroupSchema,
  type CreateLoaderTypeGroupInput,
  type DeleteQuery,
  type LoaderTypeGroupListQuery,
  type LoaderTypeGroupListResult,
  type UpdateLoaderTypeGroupInput,
} from './loader-types.schemas.js';
import type { LoaderTypeGroupDto } from './loader-types.types.js';

/**
 * Loader-type groups (F1-07 T06, ADR-011 B1). Five routes, `loader_type.read`
 * for reads and `loader_type.write` for mutations. A group with a live type is
 * `409 IN_USE` on delete; a missing, deleted or foreign row is one generic 404.
 */
@ApiTags('base-data')
@Controller('base/loader-type-groups')
export class LoaderTypeGroupsController {
  constructor(@Inject(LoaderTypesService) private readonly loaderTypes: LoaderTypesService) {}

  @RequirePermission('loader_type.read')
  @Get()
  @ApiOperation({ summary: 'List live loader-type groups (paged, filtered, sorted)' })
  async list(
    @ZodQuery(loaderTypeGroupListQuerySchema) query: LoaderTypeGroupListQuery,
    @Req() request: Request,
  ): Promise<LoaderTypeGroupListResult> {
    return this.loaderTypes.listGroups(readAuthzContext(request).scope, query);
  }

  @RequirePermission('loader_type.write')
  @Idempotent()
  @Post()
  @ApiOperation({ summary: 'Create a loader-type group' })
  async create(
    @ZodBody(createLoaderTypeGroupSchema) body: CreateLoaderTypeGroupInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<LoaderTypeGroupDto> {
    return this.loaderTypes.createGroup(readAuthzContext(request).scope, body, writeActor(request));
  }

  @RequirePermission('loader_type.read')
  @Get(':id')
  @ApiOperation({ summary: 'Read one live loader-type group' })
  async get(
    @ZodParams(loaderTypeGroupParamsSchema) params: { id: string },
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<LoaderTypeGroupDto> {
    return this.loaderTypes.getGroup(readAuthzContext(request).scope, params.id);
  }

  @RequirePermission('loader_type.write')
  @Idempotent()
  @Patch(':id')
  @ApiOperation({ summary: 'Update a loader-type group (optimistic concurrency)' })
  async update(
    @ZodParams(loaderTypeGroupParamsSchema) params: { id: string },
    @ZodBody(updateLoaderTypeGroupSchema) body: UpdateLoaderTypeGroupInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<LoaderTypeGroupDto> {
    return this.loaderTypes.updateGroup(
      readAuthzContext(request).scope,
      params.id,
      body,
      writeActor(request),
    );
  }

  @RequirePermission('loader_type.write')
  @Idempotent()
  @Delete(':id')
  @HttpCode(204)
  @ApiOperation({ summary: 'Soft-delete a group (409 IN_USE when it has live types)' })
  async remove(
    @ZodParams(loaderTypeGroupParamsSchema) params: { id: string },
    @ZodQuery(deleteQuerySchema) query: DeleteQuery,
    @Req() request: Request,
  ): Promise<void> {
    return this.loaderTypes.deleteGroup(
      readAuthzContext(request).scope,
      params.id,
      query,
      writeActor(request),
    );
  }
}
