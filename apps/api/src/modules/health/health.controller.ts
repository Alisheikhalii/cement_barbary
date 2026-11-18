import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

@ApiTags('health')
@Controller('health')
export class HealthController {
  /** Liveness: the process is up. Intentionally has no dependency checks. */
  @Get('live')
  @ApiOperation({ summary: 'Liveness probe' })
  live(): { status: 'ok' } {
    return { status: 'ok' };
  }

  /** Readiness: dependency checks (database, Redis) are added in F1-02. */
  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe' })
  ready(): { status: 'ok' } {
    return { status: 'ok' };
  }
}
