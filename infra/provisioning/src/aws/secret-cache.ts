import {
  GetSecretValueCommand,
  type GetSecretValueCommandOutput,
  type SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

export interface SecretCacheOptions {
  jsonKeys?: readonly string[];
  /** Bound warm-container staleness so secret rotation converges. */
  ttlMs?: number;
  now?: () => number;
}

export class SecretsManagerSecretCache {
  readonly #client: Pick<SecretsManagerClient, "send">;
  readonly #secretId: string;
  readonly #jsonKeys: readonly string[];
  readonly #ttlMs: number;
  readonly #now: () => number;
  #cached: Promise<string> | undefined;
  #expiresAt = 0;

  constructor(
    client: Pick<SecretsManagerClient, "send">,
    secretId: string,
    options: SecretCacheOptions = {},
  ) {
    if (!secretId) throw new Error("Secrets Manager secret ID is required");
    this.#client = client;
    this.#secretId = secretId;
    this.#jsonKeys = options.jsonKeys ?? ["webhookSecret", "stripeWebhookSecret", "secret"];
    this.#ttlMs = options.ttlMs ?? 300_000;
    this.#now = options.now ?? Date.now;
    if (!Number.isFinite(this.#ttlMs) || this.#ttlMs <= 0) {
      throw new Error("Secret cache TTL must be positive");
    }
  }

  get(): Promise<string> {
    const now = this.#now();
    if (!this.#cached || now >= this.#expiresAt) {
      const cached = this.#load().catch((error: unknown) => {
        if (this.#cached === cached) {
          this.#cached = undefined;
          this.#expiresAt = 0;
        }
        throw error;
      });
      this.#cached = cached;
      this.#expiresAt = now + this.#ttlMs;
    }
    return this.#cached;
  }

  clear(): void {
    this.#cached = undefined;
    this.#expiresAt = 0;
  }

  async #load(): Promise<string> {
    const response = (await this.#client.send(
      new GetSecretValueCommand({ SecretId: this.#secretId }),
    )) as GetSecretValueCommandOutput;
    const value = response.SecretString ?? decodeBinary(response.SecretBinary);
    if (!value) throw new Error("Secrets Manager returned an empty secret");

    const parsed = parseJsonSecret(value, this.#jsonKeys);
    if (!parsed) throw new Error("Secrets Manager secret contains no supported value");
    return parsed;
  }
}

function decodeBinary(value: Uint8Array | undefined): string | undefined {
  return value ? Buffer.from(value).toString("utf8") : undefined;
}

function parseJsonSecret(value: string, keys: readonly string[]): string {
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed !== "object" || parsed === null) return value;
    for (const key of keys) {
      const candidate = (parsed as Record<string, unknown>)[key];
      if (typeof candidate === "string" && candidate.length > 0) return candidate;
    }
    return "";
  } catch {
    return value;
  }
}
