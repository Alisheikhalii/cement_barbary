import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- value import required: emitDecoratorMetadata emits DbHealth as the constructor param type for DI
import { DbHealth } from '../../db/db-health.js';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(private readonly dbHealth: DbHealth) {}

  /** Liveness: the process is up. Intentionally has no dependency checks. */
  @Get('live')
  @ApiOperation({ summary: 'Liveness probe' })
  live(): { status: 'ok' } {
    return { status: 'ok' };
  }

  /** Readiness: 200 when the database answers, 503 (standard envelope) otherwise. */
  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe' })
  async ready(): Promise<{ status: 'ok' }> {
    try {
      await this.dbHealth.ping();
    } catch {
      // The global filter maps this to 503 with a generic message — no DB details leak.
      throw new ServiceUnavailableException();
    }
    return { status: 'ok' };
  }
}
