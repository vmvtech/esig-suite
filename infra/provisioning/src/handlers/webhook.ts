import { createHash } from "node:crypto";

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { SQSClient } from "@aws-sdk/client-sqs";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import Stripe from "stripe";

import {
  DynamoEventLedger,
  type EventClaimInput,
  type EventClaimResult,
} from "../aws/dynamo-event-ledger.js";
import {
  SqsProvisioningQueue,
  type AcceptedNormalizedStripeEvent,
} from "../aws/provisioning-queue.js";
import { SecretsManagerSecretCache } from "../aws/secret-cache.js";
import { normalizeStripeEvent } from "./normalize-stripe-event.js";

export interface StripeEventVerifier {
  constructEvent(payload: Buffer, signature: string, secret: string): Stripe.Event;
}

export const officialStripeVerifier: StripeEventVerifier = {
  constructEvent: (payload, signature, webhookSecret) =>
    Stripe.webhooks.constructEvent(payload, signature, webhookSecret),
};

export interface WebhookEventLedger {
  claimEvent(input: EventClaimInput): Promise<EventClaimResult>;
  markEnqueued(eventId: string, deliveryToken: string): Promise<void>;
}

export interface WebhookQueue {
  enqueue(event: AcceptedNormalizedStripeEvent): Promise<void>;
}

export interface WebhookSecret {
  get(): Promise<string>;
  clear(): void;
}

export interface WebhookDependencies {
  ledger: WebhookEventLedger;
  queue: WebhookQueue;
  secret: WebhookSecret;
  stripe: StripeEventVerifier;
}

export function createWebhookHandler(dependencies: WebhookDependencies) {
  return async function webhookHandler(
    request: APIGatewayProxyEventV2,
  ): Promise<APIGatewayProxyStructuredResultV2> {
    const rawBody = rawBodyFrom(request);
    const signature = header(request.headers, "stripe-signature");
    if (!rawBody || !signature) return response(400, { error: "invalid_webhook" });

    let secret: string;
    try {
      secret = await dependencies.secret.get();
    } catch {
      return response(500, { error: "secret_unavailable" });
    }

    let event: Stripe.Event;
    try {
      event = dependencies.stripe.constructEvent(rawBody, signature, secret);
    } catch {
      // Refresh once so a rotated webhook secret does not strand a warm
      // container. A second failure is a definitive bad/stale signature.
      dependencies.secret.clear();
      try {
        secret = await dependencies.secret.get();
      } catch {
        return response(500, { error: "secret_unavailable" });
      }
      try {
        event = dependencies.stripe.constructEvent(rawBody, signature, secret);
      } catch {
        return response(400, { error: "invalid_signature" });
      }
    }

    const payloadDigest = createHash("sha256").update(rawBody).digest("hex");
    const normalizedEvent = normalizeStripeEvent(event, payloadDigest);
    const shouldEnqueue = normalizedEvent.type !== "ignored";
    let claim: EventClaimResult;
    try {
      claim = await dependencies.ledger.claimEvent({
        eventId: event.id,
        eventType: event.type,
        eventCreated: event.created,
        payloadDigest,
        ...(normalizedEvent.subscriptionId === undefined
          ? {}
          : { subscriptionId: normalizedEvent.subscriptionId }),
        shouldEnqueue,
      });
    } catch {
      return response(500, { error: "event_store_unavailable" });
    }

    if (claim.outcome === "ignored") {
      return response(200, { received: true, ignored: true });
    }
    if (claim.outcome === "duplicate") {
      return response(200, { received: true, duplicate: true });
    }
    if (claim.outcome === "in-flight") {
      // Another request has not proved durable SQS delivery yet. A 2xx here can
      // make Stripe stop retrying if that lease owner subsequently fails.
      return response(500, { error: "event_delivery_in_progress" });
    }
    if (normalizedEvent.type === "ignored") {
      return response(500, { error: "event_store_inconsistent" });
    }

    try {
      await dependencies.queue.enqueue(normalizedEvent);
    } catch {
      return response(500, { error: "queue_unavailable" });
    }

    try {
      await dependencies.ledger.markEnqueued(event.id, claim.deliveryToken);
    } catch {
      return response(500, { error: "event_store_unavailable" });
    }

    return response(200, { received: true });
  };
}

function rawBodyFrom(request: APIGatewayProxyEventV2): Buffer | undefined {
  if (typeof request.body !== "string") return undefined;
  return Buffer.from(request.body, request.isBase64Encoded ? "base64" : "utf8");
}

function header(headers: Record<string, string | undefined>, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) return value;
  }
  return undefined;
}

function response(
  statusCode: number,
  body: Record<string, boolean | string>,
): APIGatewayProxyStructuredResultV2 {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

let defaultHandler: ReturnType<typeof createWebhookHandler> | undefined;

export async function handler(
  request: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> {
  defaultHandler ??= createDefaultHandler();
  return defaultHandler(request);
}

function createDefaultHandler(): ReturnType<typeof createWebhookHandler> {
  const documentClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));
  const ledger = new DynamoEventLedger(documentClient, requireEnvironment("CONTROL_PLANE_TABLE"));
  const queue = new SqsProvisioningQueue(
    new SQSClient({}),
    requireEnvironment("PROVISIONING_QUEUE_URL"),
  );
  const secret = new SecretsManagerSecretCache(
    new SecretsManagerClient({}),
    requireEnvironment("STRIPE_WEBHOOK_SECRET_ARN"),
  );

  return createWebhookHandler({
    ledger,
    queue,
    secret,
    stripe: officialStripeVerifier,
  });
}

function requireEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}
