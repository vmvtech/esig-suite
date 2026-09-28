# @e-sig/supabase

Supabase reference adapters for [`@e-sig/core`](https://github.com/vmvtech/esig-suite/tree/main/packages/esig-core) —
self-contained PDF e-signature persistence on Supabase Postgres + Storage.

```bash
npm i @e-sig/core @e-sig/supabase @supabase/supabase-js
```

Apply all three persistence migrations from the suite root, in order:

1. `migrations/0001_esig_self_contained.sql`
2. `migrations/0002_esig_audit_hashchain.sql`
3. `migrations/0003_esig_pq_keys.sql`

```ts
import { createClient } from "@supabase/supabase-js";
import {
  SupabaseCertStore,
  SupabasePqKeyStore,
  SupabaseAuditLogStore,
  SupabasePdfStorageStore,
  verifyAuditChain,
} from "@e-sig/supabase";

const service = createClient(url, serviceRoleKey); // service-role: bypasses RLS for cert/audit/storage writes

const certStore = new SupabaseCertStore(service);          // table "org_signing_certs", tenant col "tenant_id"
const pqKeyStore = new SupabasePqKeyStore(service);        // table "org_pq_keys", tenant col "tenant_id"
const auditStore = new SupabaseAuditLogStore(service);     // table "esig_audit_log"
const storage = new SupabasePdfStorageStore(service);      // bucket "signed-documents"
```

All three constructors take options to map onto an existing schema, e.g. the
Opendelphi schema keys on `org_id`:

```ts
new SupabaseCertStore(service, { table: "org_signing_certs", tenantColumn: "org_id" });
new SupabasePqKeyStore(service, { table: "org_pq_keys", tenantColumn: "org_id" });
new SupabaseAuditLogStore(service, { tenantColumn: "org_id" });
new SupabasePdfStorageStore(service, { bucket: "signed-documents" });
```

`SupabasePqKeyStore` implements core's `PqKeyStore` interface for encrypted
Ed25519 + ML-DSA-65 key bundles. Its constructor signature is
`new SupabasePqKeyStore(client, { table?, tenantColumn? })`; use it with
`ensureActivePqKeys` and `rotatePqKeys` from `@e-sig/core`.

Verify one tenant's audit hash chain with the exported checker:

```ts
const result = await verifyAuditChain(service, {
  tenantId,
  // Optional: table, tenantColumn, pageSize
});

if (!result.ok) {
  console.error(result.firstBrokenSeq, result.failures);
}
```

`verifyAuditChain(client, options)` returns `{ ok, checkedRows,
firstBrokenSeq?, failures }`; `options` requires `tenantId` and optionally
accepts `table`, `tenantColumn`, and `pageSize`.

Pass `certStore`, `auditStore`, and `storage` to `signDocument()` from
`@e-sig/core`. Those stores handle the Postgres `\x`-hex bytea round-trip for
the encrypted key and return the storage **path** (private buckets have no
public URL — serve via an RLS-gated download route).

Peer deps: `@e-sig/core`, `@supabase/supabase-js`. License: MIT.
