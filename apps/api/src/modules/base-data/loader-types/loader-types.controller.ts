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
  createLoaderTypeSchema,
  deleteQuerySchema,
  emptyQuerySchema,
  loaderTypeListQuerySchema,
  loaderTypeParamsSchema,
  updateLoaderTypeSchema,
  type CreateLoaderTypeInput,
  type DeleteQuery,
  type LoaderTypeListQuery,
  type LoaderTypeListResult,
  type UpdateLoaderTypeInput,
} from './loader-types.schemas.js';
import type { LoaderTypeDto } from './loader-types.types.js';

/**
 * Loader types (F1-07 T06, ADR-011 B1). Five routes, `loader_type.read` for
 * reads and `loader_type.write` for mutations. `groupId` is a body field on
 * create and may be changed by PATCH (a move); an unknown/deleted/foreign
 * group is the same generic 404 as a missing type.
 */
@ApiTags('base-data')
@Controller('base/loader-types')
export class LoaderTypesController {
  constructor(@Inject(LoaderTypesService) private readonly loaderTypes: LoaderTypesService) {}

  @RequirePermission('loader_type.read')
  @Get()
  @ApiOperation({ summary: 'List live loader types (paged, filterable by group)' })
  async list(
    @ZodQuery(loaderTypeListQuerySchema) query: LoaderTypeListQuery,
    @Req() request: Request,
  ): Promise<LoaderTypeListResult> {
    return this.loaderTypes.listTypes(readAuthzContext(request).scope, query);
  }

  @RequirePermission('loader_type.write')
  @Idempotent()
  @Post()
  @ApiOperation({ summary: 'Create a loader type in a group' })
  async create(
    @ZodBody(createLoaderTypeSchema) body: CreateLoaderTypeInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<LoaderTypeDto> {
    return this.loaderTypes.createType(readAuthzContext(request).scope, body, writeActor(request));
  }

  @RequirePermission('loader_type.read')
  @Get(':id')
  @ApiOperation({ summary: 'Read one live loader type' })
  async get(
    @ZodParams(loaderTypeParamsSchema) params: { id: string },
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<LoaderTypeDto> {
    return this.loaderTypes.getType(readAuthzContext(request).scope, params.id);
  }

  @RequirePermission('loader_type.write')
  @Idempotent()
  @Patch(':id')
  @ApiOperation({ summary: 'Update or move a loader type (optimistic concurrency)' })
  async update(
    @ZodParams(loaderTypeParamsSchema) params: { id: string },
    @ZodBody(updateLoaderTypeSchema) body: UpdateLoaderTypeInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<LoaderTypeDto> {
    return this.loaderTypes.updateType(
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
  @ApiOperation({ summary: 'Soft-delete a loader type' })
  async remove(
    @ZodParams(loaderTypeParamsSchema) params: { id: string },
    @ZodQuery(deleteQuerySchema) query: DeleteQuery,
    @Req() request: Request,
  ): Promise<void> {
    return this.loaderTypes.deleteType(
      readAuthzContext(request).scope,
      params.id,
      query,
      writeActor(request),
    );
  }
}
