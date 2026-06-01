# @vmvtech/esig-supabase

Supabase reference adapters for [`@vmvtech/esig-core`](https://github.com/vmvtech/esig-suite/tree/main/packages/esig-core) —
self-contained PDF e-signature persistence on Supabase Postgres + Storage.

```bash
npm i @vmvtech/esig-core @vmvtech/esig-supabase @supabase/supabase-js
```

Apply `migrations/0001_esig_self_contained.sql` (in the suite root) first.

```ts
import { createClient } from "@supabase/supabase-js";
import {
  SupabaseCertStore,
  SupabaseAuditLogStore,
  SupabasePdfStorageStore,
} from "@vmvtech/esig-supabase";

const service = createClient(url, serviceRoleKey); // service-role: bypasses RLS for cert/audit/storage writes

const certStore = new SupabaseCertStore(service);          // table "org_signing_certs", tenant col "tenant_id"
const auditStore = new SupabaseAuditLogStore(service);     // table "esig_audit_log"
const storage = new SupabasePdfStorageStore(service);      // bucket "signed-documents"
```

All three constructors take options to map onto an existing schema, e.g. the
Opendelphi schema keys on `org_id`:

```ts
new SupabaseCertStore(service, { table: "org_signing_certs", tenantColumn: "org_id" });
new SupabaseAuditLogStore(service, { tenantColumn: "org_id" });
new SupabasePdfStorageStore(service, { bucket: "signed-documents" });
```

Pass these to `signDocument()` from `@vmvtech/esig-core`. The stores handle the
Postgres `\x`-hex bytea round-trip for the encrypted key and return the storage
**path** (private buckets have no public URL — serve via an RLS-gated download route).

Peer deps: `@vmvtech/esig-core`, `@supabase/supabase-js`. License: MIT.
