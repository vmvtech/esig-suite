import type { APIGatewayProxyEventV2 } from "aws-lambda";
import Stripe from "stripe";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createWebhookHandler,
  officialStripeVerifier,
  type WebhookDependencies,
} from "../src/handlers/webhook.js";

describe("Stripe webhook handler", () => {
  let dependencies: WebhookDependencies;

  beforeEach(() => {
    dependencies = {
      secret: {
        get: vi.fn().mockResolvedValue("whsec_test"),
        clear: vi.fn(),
      },
      stripe: { constructEvent: vi.fn().mockReturnValue(stripeEvent()) },
      ledger: {
        claimEvent: vi
          .fn()
          .mockResolvedValue({ outcome: "deliver", deliveryToken: "delivery-token" }),
        markEnqueued: vi.fn().mockResolvedValue(undefined),
      },
      queue: { enqueue: vi.fn().mockResolvedValue(undefined) },
    };
  });

  it("delegates verification to Stripe's official webhook implementation", () => {
    const event = stripeEvent();
    const constructEvent = vi
      .spyOn(Stripe.webhooks, "constructEvent")
      .mockReturnValue(event);
    const payload = Buffer.from('{"id":"evt_123"}');

    expect(officialStripeVerifier.constructEvent(payload, "signature", "secret")).toBe(event);
    expect(constructEvent).toHaveBeenCalledWith(payload, "signature", "secret");
  });

  it("accepts a valid official Stripe test signature and rejects stale or malformed ones", () => {
    const secret = "whsec_unit_test_only";
    const payload = JSON.stringify(stripeEvent());
    const currentTimestamp = Math.floor(Date.now() / 1_000);
    const validSignature = Stripe.webhooks.generateTestHeaderString({
      payload,
      secret,
      timestamp: currentTimestamp,
    });
    const staleSignature = Stripe.webhooks.generateTestHeaderString({
      payload,
      secret,
      timestamp: currentTimestamp - 301,
    });

    expect(
      officialStripeVerifier.constructEvent(Buffer.from(payload), validSignature, secret),
    ).toMatchObject({ id: "evt_123", type: "invoice.paid" });
    expect(() =>
      officialStripeVerifier.constructEvent(Buffer.from(payload), staleSignature, secret),
    ).toThrow(/timestamp/i);
    expect(() =>
      officialStripeVerifier.constructEvent(Buffer.from(payload), "malformed", secret),
    ).toThrow();
  });

  it("preserves the API Gateway v2 raw body through official-verifier boundary", async () => {
    const raw = '{"id":"evt_123", "spacing":"must survive"}';
    const handler = createWebhookHandler(dependencies);

    const result = await handler(request(raw));

    expect(result.statusCode).toBe(200);
    expect(dependencies.stripe.constructEvent).toHaveBeenCalledWith(
      Buffer.from(raw),
      "t=123,v1=fake",
      "whsec_test",
    );
    expect(dependencies.ledger.claimEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        eventId: "evt_123",
        eventType: "invoice.paid",
        shouldEnqueue: true,
      }),
    );
    expect(dependencies.queue.enqueue).toHaveBeenCalledTimes(1);
    expect(dependencies.ledger.markEnqueued).toHaveBeenCalledWith(
      "evt_123",
      "delivery-token",
    );
  });

  it("decodes a base64 API Gateway body without parsing and reserializing it", async () => {
    const raw = '{"id":"evt_base64"}\n';
    const handler = createWebhookHandler(dependencies);

    await handler(request(Buffer.from(raw).toString("base64"), true));

    expect(dependencies.stripe.constructEvent).toHaveBeenCalledWith(
      Buffer.from(raw),
      expect.any(String),
      expect.any(String),
    );
  });

  it("returns 400 for an invalid Stripe signature before touching AWS state", async () => {
    vi.mocked(dependencies.stripe.constructEvent).mockImplementation(() => {
      throw new Error("No signatures found matching the expected signature");
    });
    const handler = createWebhookHandler(dependencies);

    const result = await handler(request("{}"));

    expect(result.statusCode).toBe(400);
    expect(dependencies.secret.clear).toHaveBeenCalledTimes(1);
    expect(dependencies.secret.get).toHaveBeenCalledTimes(2);
    expect(dependencies.ledger.claimEvent).not.toHaveBeenCalled();
    expect(dependencies.queue.enqueue).not.toHaveBeenCalled();
  });

  it("refreshes a rotated webhook secret once before rejecting the signature", async () => {
    vi.mocked(dependencies.secret.get)
      .mockResolvedValueOnce("whsec_old")
      .mockResolvedValueOnce("whsec_new");
    vi.mocked(dependencies.stripe.constructEvent).mockImplementation(
      (_payload, _signature, secret) => {
        if (secret === "whsec_old") throw new Error("signature mismatch");
        return stripeEvent();
      },
    );
    const handler = createWebhookHandler(dependencies);

    await expect(handler(request("{}"))).resolves.toMatchObject({ statusCode: 200 });

    expect(dependencies.secret.clear).toHaveBeenCalledTimes(1);
    expect(dependencies.secret.get).toHaveBeenCalledTimes(2);
    expect(dependencies.queue.enqueue).toHaveBeenCalledTimes(1);
  });

  it("returns 400 when the signature header or raw body is absent", async () => {
    const handler = createWebhookHandler(dependencies);
    const missingSignature = request("{}");
    missingSignature.headers = {};
    const missingBody = request("{}");
    delete (missingBody as { body?: string }).body;

    await expect(handler(missingSignature)).resolves.toMatchObject({ statusCode: 400 });
    await expect(handler(missingBody)).resolves.toMatchObject({ statusCode: 400 });
    expect(dependencies.secret.get).not.toHaveBeenCalled();
  });

  it("acknowledges an already-enqueued duplicate without another SQS call", async () => {
    vi.mocked(dependencies.ledger.claimEvent).mockResolvedValue({ outcome: "duplicate" });
    const handler = createWebhookHandler(dependencies);

    const result = await handler(request("{}"));

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body!)).toMatchObject({ duplicate: true });
    expect(dependencies.queue.enqueue).not.toHaveBeenCalled();
    expect(dependencies.ledger.markEnqueued).not.toHaveBeenCalled();
  });

  it("allows only one active sender and keeps in-flight duplicates retryable", async () => {
    let claimed = false;
    vi.mocked(dependencies.ledger.claimEvent).mockImplementation(async () => {
      if (claimed) return { outcome: "in-flight" };
      claimed = true;
      return { outcome: "deliver", deliveryToken: "winner" };
    });
    const handler = createWebhookHandler(dependencies);

    const results = await Promise.all(
      Array.from({ length: 10 }, () => handler(request('{"id":"evt_123"}'))),
    );

    expect(results.filter((result) => result.statusCode === 200)).toHaveLength(1);
    expect(results.filter((result) => result.statusCode === 500)).toHaveLength(9);
    expect(dependencies.queue.enqueue).toHaveBeenCalledTimes(1);
    expect(dependencies.ledger.markEnqueued).toHaveBeenCalledTimes(1);
  });

  it("does not acknowledge an in-flight duplicate when the lease owner may fail enqueue", async () => {
    vi.mocked(dependencies.ledger.claimEvent).mockResolvedValue({ outcome: "in-flight" });
    const handler = createWebhookHandler(dependencies);

    await expect(handler(request("{}"))).resolves.toMatchObject({ statusCode: 500 });
    expect(dependencies.queue.enqueue).not.toHaveBeenCalled();
    expect(dependencies.ledger.markEnqueued).not.toHaveBeenCalled();
  });

  it("keeps both concurrent responses retryable when the lease owner's enqueue fails", async () => {
    let claimed = false;
    vi.mocked(dependencies.ledger.claimEvent).mockImplementation(async () => {
      if (claimed) return { outcome: "in-flight" };
      claimed = true;
      return { outcome: "deliver", deliveryToken: "winner" };
    });
    vi.mocked(dependencies.queue.enqueue).mockRejectedValue(new Error("temporary"));
    const handler = createWebhookHandler(dependencies);

    const results = await Promise.all([handler(request("{}")), handler(request("{}"))]);

    expect(results.map((result) => result.statusCode)).toEqual([500, 500]);
    expect(dependencies.queue.enqueue).toHaveBeenCalledTimes(1);
    expect(dependencies.ledger.markEnqueued).not.toHaveBeenCalled();
  });

  it("records and acknowledges unknown event types without queueing them", async () => {
    vi.mocked(dependencies.stripe.constructEvent).mockReturnValue(
      stripeEvent("radar.early_fraud_warning.created"),
    );
    vi.mocked(dependencies.ledger.claimEvent).mockResolvedValue({ outcome: "ignored" });
    const handler = createWebhookHandler(dependencies);

    const result = await handler(request("{}"));

    expect(result.statusCode).toBe(200);
    expect(dependencies.ledger.claimEvent).toHaveBeenCalledWith(
      expect.objectContaining({ shouldEnqueue: false }),
    );
    expect(dependencies.queue.enqueue).not.toHaveBeenCalled();
  });

  it("returns 500 for secret, DynamoDB, queue, and post-enqueue store failures", async () => {
    const handler = createWebhookHandler(dependencies);

    vi.mocked(dependencies.secret.get).mockRejectedValueOnce(new Error("temporary"));
    await expect(handler(request("{}"))).resolves.toMatchObject({ statusCode: 500 });

    vi.mocked(dependencies.ledger.claimEvent).mockRejectedValueOnce(new Error("temporary"));
    await expect(handler(request("{}"))).resolves.toMatchObject({ statusCode: 500 });

    vi.mocked(dependencies.queue.enqueue).mockRejectedValueOnce(new Error("temporary"));
    await expect(handler(request("{}"))).resolves.toMatchObject({ statusCode: 500 });

    vi.mocked(dependencies.ledger.markEnqueued).mockRejectedValueOnce(new Error("temporary"));
    await expect(handler(request("{}"))).resolves.toMatchObject({ statusCode: 500 });
  });
});

function request(body: string, isBase64Encoded = false): APIGatewayProxyEventV2 {
  return {
    version: "2.0",
    routeKey: "POST /webhooks/stripe",
    rawPath: "/webhooks/stripe",
    rawQueryString: "",
    headers: { "stripe-signature": "t=123,v1=fake" },
    requestContext: {
      accountId: "123456789012",
      apiId: "api",
      domainName: "example.execute-api.us-east-1.amazonaws.com",
      domainPrefix: "example",
      http: {
        method: "POST",
        path: "/webhooks/stripe",
        protocol: "HTTP/1.1",
        sourceIp: "127.0.0.1",
        userAgent: "vitest",
      },
      requestId: "request-id",
      routeKey: "POST /webhooks/stripe",
      stage: "$default",
      time: "04/Aug/2026:12:00:00 +0000",
      timeEpoch: 1_785_844_800_000,
    },
    body,
    isBase64Encoded,
  };
}

function stripeEvent(type = "invoice.paid"): Stripe.Event {
  return {
    id: "evt_123",
    object: "event",
    api_version: "2026-07-29.basil",
    created: 1_785_844_800,
    data: { object: { subscription: "sub_123" } },
    livemode: false,
    pending_webhooks: 1,
    request: null,
    type,
  } as Stripe.Event;
}
