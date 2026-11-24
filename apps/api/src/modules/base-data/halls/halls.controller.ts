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
import { HallsService } from './halls.service.js';
import {
  createHallSchema,
  createTerminalSchema,
  deleteQuerySchema,
  emptyQuerySchema,
  hallIdParamsSchema,
  hallListQuerySchema,
  hallParamsSchema,
  terminalListQuerySchema,
  terminalParamsSchema,
  updateHallSchema,
  updateTerminalSchema,
  type CreateHallInput,
  type CreateTerminalInput,
  type DeleteQuery,
  type HallListQuery,
  type HallListResult,
  type TerminalListQuery,
  type TerminalListResult,
  type UpdateHallInput,
  type UpdateTerminalInput,
} from './halls.schemas.js';
import type { HallDto, TerminalDto } from './halls.types.js';

/**
 * Halls and their nested terminals (F1-07 T05, ADR-011 B1).
 *
 * Ten routes, `hall.read` for reads and `hall.write` for mutations. A
 * terminal's hall exists only in the path; every terminal query is scoped by
 * tenant AND hall, so another hall's path is the same 404 as a missing row.
 */
@ApiTags('base-data')
@Controller('base/halls')
export class HallsController {
  constructor(@Inject(HallsService) private readonly halls: HallsService) {}

  @RequirePermission('hall.read')
  @Get()
  @ApiOperation({ summary: 'List live halls (paged, filtered, sorted)' })
  async list(
    @ZodQuery(hallListQuerySchema) query: HallListQuery,
    @Req() request: Request,
  ): Promise<HallListResult> {
    return this.halls.list(readAuthzContext(request).scope, query);
  }

  @RequirePermission('hall.write')
  @Idempotent()
  @Post()
  @ApiOperation({ summary: 'Create a hall' })
  async create(
    @ZodBody(createHallSchema) body: CreateHallInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<HallDto> {
    return this.halls.create(readAuthzContext(request).scope, body, writeActor(request));
  }

  @RequirePermission('hall.read')
  @Get(':id')
  @ApiOperation({ summary: 'Read one live hall' })
  async get(
    @ZodParams(hallParamsSchema) params: { id: string },
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<HallDto> {
    return this.halls.get(readAuthzContext(request).scope, params.id);
  }

  @RequirePermission('hall.write')
  @Idempotent()
  @Patch(':id')
  @ApiOperation({ summary: 'Update a hall (optimistic concurrency)' })
  async update(
    @ZodParams(hallParamsSchema) params: { id: string },
    @ZodBody(updateHallSchema) body: UpdateHallInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<HallDto> {
    return this.halls.update(readAuthzContext(request).scope, params.id, body, writeActor(request));
  }

  @RequirePermission('hall.write')
  @Idempotent()
  @Delete(':id')
  @HttpCode(204)
  @ApiOperation({ summary: 'Soft-delete a hall (409 IN_USE when it has live terminals)' })
  async remove(
    @ZodParams(hallParamsSchema) params: { id: string },
    @ZodQuery(deleteQuerySchema) query: DeleteQuery,
    @Req() request: Request,
  ): Promise<void> {
    return this.halls.delete(
      readAuthzContext(request).scope,
      params.id,
      query,
      writeActor(request),
    );
  }

  // ---------- nested terminals ----------

  @RequirePermission('hall.read')
  @Get(':hallId/terminals')
  @ApiOperation({ summary: 'List live terminals of one hall' })
  async listTerminals(
    @ZodParams(hallIdParamsSchema) params: { hallId: string },
    @ZodQuery(terminalListQuerySchema) query: TerminalListQuery,
    @Req() request: Request,
  ): Promise<TerminalListResult> {
    return this.halls.listTerminals(readAuthzContext(request).scope, params.hallId, query);
  }

  @RequirePermission('hall.write')
  @Idempotent()
  @Post(':hallId/terminals')
  @ApiOperation({ summary: 'Create a terminal under a hall' })
  async createTerminal(
    @ZodParams(hallIdParamsSchema) params: { hallId: string },
    @ZodBody(createTerminalSchema) body: CreateTerminalInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<TerminalDto> {
    return this.halls.createTerminal(
      readAuthzContext(request).scope,
      params.hallId,
      body,
      writeActor(request),
    );
  }

  @RequirePermission('hall.read')
  @Get(':hallId/terminals/:id')
  @ApiOperation({ summary: 'Read one live terminal of a hall' })
  async getTerminal(
    @ZodParams(terminalParamsSchema) params: { hallId: string; id: string },
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<TerminalDto> {
    return this.halls.getTerminal(readAuthzContext(request).scope, params.hallId, params.id);
  }

  @RequirePermission('hall.write')
  @Idempotent()
  @Patch(':hallId/terminals/:id')
  @ApiOperation({ summary: 'Update a terminal (optimistic concurrency)' })
  async updateTerminal(
    @ZodParams(terminalParamsSchema) params: { hallId: string; id: string },
    @ZodBody(updateTerminalSchema) body: UpdateTerminalInput,
    @ZodQuery(emptyQuerySchema) _query: Record<string, never>,
    @Req() request: Request,
  ): Promise<TerminalDto> {
    return this.halls.updateTerminal(
      readAuthzContext(request).scope,
      params.hallId,
      params.id,
      body,
      writeActor(request),
    );
  }

  @RequirePermission('hall.write')
  @Idempotent()
  @Delete(':hallId/terminals/:id')
  @HttpCode(204)
  @ApiOperation({ summary: 'Soft-delete a terminal' })
  async removeTerminal(
    @ZodParams(terminalParamsSchema) params: { hallId: string; id: string },
    @ZodQuery(deleteQuerySchema) query: DeleteQuery,
    @Req() request: Request,
  ): Promise<void> {
    return this.halls.deleteTerminal(
      readAuthzContext(request).scope,
      params.hallId,
      params.id,
      query,
      writeActor(request),
    );
  }
}
