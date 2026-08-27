import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { DEDICATED_MIGRATION_SOURCES } from "../src/providers/dedicated-migrations.js";
import { DEDICATED_REQUIRED_MIGRATIONS } from "../src/providers/dedicated.js";

const sha256 = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");

describe("dedicated migration bundle", () => {
  it("is frozen, complete, ordered, and non-empty", () => {
    expect(Object.isFrozen(DEDICATED_MIGRATION_SOURCES)).toBe(true);
    expect(DEDICATED_MIGRATION_SOURCES.map(({ name }) => name)).toEqual(
      DEDICATED_REQUIRED_MIGRATIONS,
    );

    for (const migration of DEDICATED_MIGRATION_SOURCES) {
      expect(Object.isFrozen(migration)).toBe(true);
      expect(migration.sql.trim().length).toBeGreaterThan(0);
    }
  });

  it("contains byte-equivalent text for each repository migration", async () => {
    for (const migration of DEDICATED_MIGRATION_SOURCES) {
      const sourceUrl = new URL(`../../../migrations/${migration.name}`, import.meta.url);
      const sourceBytes = await readFile(sourceUrl);

      expect(Buffer.byteLength(migration.sql, "utf8")).toBe(sourceBytes.byteLength);
      expect(sha256(migration.sql)).toBe(sha256(sourceBytes));
    }
  });
});
