import migration0001 from "../../../../migrations/0001_esig_self_contained.sql?raw";
import migration0002 from "../../../../migrations/0002_esig_audit_hashchain.sql?raw";
import migration0003 from "../../../../migrations/0003_esig_pq_keys.sql?raw";
import migration0004 from "../../../../migrations/0004_esig_cloud_tenants.sql?raw";

import { DEDICATED_REQUIRED_MIGRATIONS } from "./dedicated.js";
import type { SupabaseDedicatedMigrationSource } from "./supabase-dedicated-bootstrapper.js";

/**
 * Exact repository migration text embedded into the Lambda bundle at build
 * time. Both the array and its records are frozen so runtime composition
 * cannot reorder or replace a migration after bootstrapper construction.
 */
export const DEDICATED_MIGRATION_SOURCES = Object.freeze([
  Object.freeze({
    name: DEDICATED_REQUIRED_MIGRATIONS[0],
    sql: migration0001,
  }),
  Object.freeze({
    name: DEDICATED_REQUIRED_MIGRATIONS[1],
    sql: migration0002,
  }),
  Object.freeze({
    name: DEDICATED_REQUIRED_MIGRATIONS[2],
    sql: migration0003,
  }),
  Object.freeze({
    name: DEDICATED_REQUIRED_MIGRATIONS[3],
    sql: migration0004,
  }),
] satisfies readonly SupabaseDedicatedMigrationSource[]);
