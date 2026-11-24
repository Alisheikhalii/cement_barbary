import { Module } from '@nestjs/common';

import { AuditModule } from '../../audit/audit.module.js';
import { LoaderTypeGroupsController } from './loader-type-groups.controller.js';
import { LoaderTypeGroupReferences } from './loader-type-group-references.js';
import { LoaderTypeGroupsRepository } from './loader-type-groups.repository.js';
import { LoaderTypesController } from './loader-types.controller.js';
import { LoaderTypesRepository } from './loader-types.repository.js';
import { LoaderTypesService } from './loader-types.service.js';

/**
 * Loader-type groups + loader types (F1-07 T06). DatabaseModule is global;
 * AuditModule supplies the transactional writer for `loader_type_group.*` and
 * `loader_type.*`.
 */
@Module({
  imports: [AuditModule],
  controllers: [LoaderTypeGroupsController, LoaderTypesController],
  providers: [
    LoaderTypeGroupsRepository,
    LoaderTypesRepository,
    LoaderTypeGroupReferences,
    LoaderTypesService,
  ],
})
export class LoaderTypesModule {}
