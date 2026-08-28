// email/aws-ses-ambient.d.ts
//
// Minimal ambient shape for the OPTIONAL peer dependency
// `@aws-sdk/client-sesv2` (package.json `peerDependenciesMeta`) — this
// package never installs it (HARD RAILS: no new hard third-party deps), so
// there is no real `node_modules/@aws-sdk/client-sesv2/**` for `tsc` to
// resolve types from. This ambient declaration is JUST enough for
// `transport.ts`'s dynamic `import("@aws-sdk/client-sesv2")` to type-check;
// at runtime the dynamic import resolves against whatever the OPERATOR
// installed (real shape, real types at their build time) — this file has no
// runtime effect at all.

declare module "@aws-sdk/client-sesv2" {
  export class SESv2Client {
    constructor(config: { region: string });
    send(command: unknown): Promise<{ MessageId?: string }>;
  }
  export class SendEmailCommand {
    constructor(input: unknown);
  }
}
