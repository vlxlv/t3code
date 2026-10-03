import * as Context from "effect/Context";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as HttpClient from "effect/unstable/http/HttpClient";
import * as HttpClientRequest from "effect/unstable/http/HttpClientRequest";
import * as HttpRouter from "effect/unstable/http/HttpRouter";
import type * as HttpServerRequest from "effect/unstable/http/HttpServerRequest";
import * as HttpServerResponse from "effect/unstable/http/HttpServerResponse";

import * as RelayConfiguration from "../Config.ts";
import { validateManagedEndpoint, withoutRedirects } from "../environments/EnvironmentConnector.ts";
import * as EnvironmentLinks from "../environments/EnvironmentLinks.ts";
import * as ManagedEndpointAllocations from "../environments/ManagedEndpointAllocations.ts";

export const RELAY_HOOK_PATH_PREFIX = "/v1/hooks/";
export const RELAY_HOOK_ROUTE = "/v1/hooks/:environmentId/:hookId/:token";
export const RELAY_HOOK_MAX_BODY_BYTES = 1_048_576;
export const RELAY_HOOK_UPSTREAM_TIMEOUT_MS = 8_000;
export const RELAY_HOOK_RATE_LIMIT = { limit: 60, periodSeconds: 60 } as const;

const FORWARDED_METHODS = new Set(["GET", "POST", "PUT", "PATCH"]);
const DROPPED_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "upgrade",
  "content-length",
  "cookie",
  "x-real-ip",
]);
const DROPPED_REQUEST_HEADER_PREFIXES = ["proxy-", "cf-", "x-forwarded-"];
// Cloudflare answers 530 when the tunnel for a hostname has no connected origin.
const TUNNEL_OFFLINE_STATUS = 530;

export const isRelayHookPath = (url: string): boolean => url.startsWith(RELAY_HOOK_PATH_PREFIX);

/** Replaces the hook token (and any query) so traces and logs never record the secret. */
export const redactRelayHookUrl = (url: string): string => {
  const path = url.split("?", 1)[0] ?? url;
  const segments = path.split("/");
  if (segments.length >= 6) {
    segments[5] = "<redacted>";
  }
  return segments.join("/");
};

/**
 * Request budget for public hook forwarding, keyed by a hash of the full hook
 * URL (environment, hook and token). Requests with a wrong token get their own
 * budget, so they cannot use up a real sender's; the environment rejects them.
 */
const hookBudgetKey = (hook: {
  readonly environmentId: string;
  readonly rawHookId: string;
  readonly rawToken: string;
}) =>
  Effect.promise(() =>
    crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`${hook.environmentId}/${hook.rawHookId}/${hook.rawToken}`),
    ),
  ).pipe(
    Effect.map((digest) =>
      Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""),
    ),
  );

export class HookRateLimiter extends Context.Service<
  HookRateLimiter,
  { readonly allow: (key: string) => Effect.Effect<boolean> }
>()("t3code-relay/hooks/HookForwarder/HookRateLimiter") {}

export class HookForwarder extends Context.Service<
  HookForwarder,
  {
    readonly handle: (
      request: HttpServerRequest.HttpServerRequest,
    ) => Effect.Effect<HttpServerResponse.HttpServerResponse>;
  }
>()("t3code-relay/hooks/HookForwarder") {}

class HookBodyTooLarge extends Schema.TaggedError<HookBodyTooLarge>()("HookBodyTooLarge", {}) {}

const errorResponse = (status: number, error: string, headers?: Record<string, string>) =>
  HttpServerResponse.jsonUnsafe({ error }, { status, ...(headers ? { headers } : {}) });

const hookNotFound = () => errorResponse(404, "hook_not_found");

function parseHookPath(url: string) {
  const queryIndex = url.indexOf("?");
  const path = queryIndex === -1 ? url : url.slice(0, queryIndex);
  const search = queryIndex === -1 ? "" : url.slice(queryIndex);
  const segments = path.split("/");
  // ["", "v1", "hooks", environmentId, hookId, token]
  if (segments.length !== 6) return null;
  const [, , , rawEnvironmentId, rawHookId, rawToken] = segments;
  if (!rawEnvironmentId || !rawHookId || !rawToken) return null;
  try {
    return {
      environmentId: decodeURIComponent(rawEnvironmentId),
      hookId: decodeURIComponent(rawHookId),
      // Forward the encoded segments byte-for-byte; the environment decodes them.
      rawHookId,
      rawToken,
      search,
    };
  } catch {
    return null;
  }
}

function forwardedHeaders(headers: Readonly<Record<string, string>>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name in headers) {
    const lower = name.toLowerCase();
    if (
      DROPPED_REQUEST_HEADERS.has(lower) ||
      DROPPED_REQUEST_HEADER_PREFIXES.some((prefix) => lower.startsWith(prefix))
    ) {
      continue;
    }
    const value = headers[name];
    if (value !== undefined) result[lower] = value;
  }
  return result;
}

const hasNoBody = (request: HttpServerRequest.HttpServerRequest) =>
  request.source instanceof Request && request.source.body === null;

const readCappedBody = (request: HttpServerRequest.HttpServerRequest) =>
  Effect.suspend(() => {
    if (hasNoBody(request)) {
      return Effect.succeed(new Uint8Array(0));
    }
    const chunks: Array<Uint8Array> = [];
    let total = 0;
    return request.stream.pipe(
      Stream.runForEach((chunk) => {
        total += chunk.length;
        if (total > RELAY_HOOK_MAX_BODY_BYTES) {
          return Effect.fail(new HookBodyTooLarge());
        }
        chunks.push(chunk);
        return Effect.void;
      }),
      Effect.map(() => {
        const body = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
          body.set(chunk, offset);
          offset += chunk.length;
        }
        return body;
      }),
    );
  });

const make = Effect.gen(function* () {
  const links = yield* EnvironmentLinks.EnvironmentLinks;
  const allocations = yield* ManagedEndpointAllocations.ManagedEndpointAllocations;
  const settings = yield* RelayConfiguration.RelayConfiguration;
  const httpClient = yield* HttpClient.HttpClient;
  const rateLimiter = yield* HookRateLimiter;

  const resolveEndpoint = Effect.fn("relay.hooks.resolve_endpoint")(function* (
    environmentId: string,
  ) {
    const candidates = yield* links.findActiveManagedForEnvironment({ environmentId });
    for (const link of candidates) {
      const allocation = yield* allocations.get({ userId: link.userId, environmentId });
      const result = validateManagedEndpoint({
        link,
        allocation,
        baseDomain: settings.managedEndpointBaseDomain,
      });
      if (Result.isSuccess(result)) {
        return result.success;
      }
    }
    return null;
  });

  const handle = Effect.fn("relay.hooks.forward")(function* (
    request: HttpServerRequest.HttpServerRequest,
  ) {
    const outcome = (value: string) => Effect.annotateCurrentSpan({ "relay.hook.outcome": value });
    const parsed = parseHookPath(request.url);
    if (!parsed) {
      yield* outcome("invalid_path");
      return hookNotFound();
    }
    yield* Effect.annotateCurrentSpan({
      "relay.environment_id": parsed.environmentId,
      "relay.hook_id": parsed.hookId,
    });
    if (!FORWARDED_METHODS.has(request.method)) {
      yield* outcome("method_not_allowed");
      return errorResponse(405, "method_not_allowed", { allow: "GET, POST, PUT, PATCH" });
    }
    if (!(yield* rateLimiter.allow(yield* hookBudgetKey(parsed)))) {
      yield* outcome("rate_limited");
      return errorResponse(429, "rate_limited", {
        "retry-after": String(RELAY_HOOK_RATE_LIMIT.periodSeconds),
      });
    }
    const declaredLength = Number(request.headers["content-length"] ?? "0");
    if (Number.isFinite(declaredLength) && declaredLength > RELAY_HOOK_MAX_BODY_BYTES) {
      yield* outcome("payload_too_large");
      return errorResponse(413, "payload_too_large");
    }

    const endpoint = yield* resolveEndpoint(parsed.environmentId).pipe(
      Effect.catch((error) =>
        Effect.logWarning("Failed to resolve hook endpoint", {
          environmentId: parsed.environmentId,
          errorTag: error._tag,
        }).pipe(Effect.as(null)),
      ),
    );
    if (!endpoint) {
      yield* outcome("not_found");
      return hookNotFound();
    }

    const body =
      request.method === "GET"
        ? Result.succeed(new Uint8Array(0))
        : yield* readCappedBody(request).pipe(Effect.result);
    if (Result.isFailure(body)) {
      if (body.failure._tag === "HookBodyTooLarge") {
        yield* outcome("payload_too_large");
        return errorResponse(413, "payload_too_large");
      }
      yield* outcome("invalid_body");
      return errorResponse(400, "invalid_body");
    }

    const baseUrl = endpoint.httpBaseUrl.endsWith("/")
      ? endpoint.httpBaseUrl
      : `${endpoint.httpBaseUrl}/`;
    const headers = forwardedHeaders(request.headers);
    let upstreamRequest = HttpClientRequest.make(
      request.method as "GET" | "POST" | "PUT" | "PATCH",
    )(`${baseUrl}api/hooks/${parsed.rawHookId}/${parsed.rawToken}${parsed.search}`, { headers });
    if (request.method !== "GET") {
      upstreamRequest = HttpClientRequest.bodyUint8Array(
        upstreamRequest,
        body.success,
        headers["content-type"],
      );
    }

    const upstream = yield* httpClient.execute(upstreamRequest).pipe(
      Effect.flatMap((response) =>
        response.arrayBuffer.pipe(
          Effect.map((bytes) => ({
            status: response.status,
            contentType: response.headers["content-type"],
            body: new Uint8Array(bytes),
          })),
        ),
      ),
      withoutRedirects,
      // The client span would record url.full, which carries the token.
      Effect.provideService(HttpClient.TracerDisabledWhen, () => true),
      Effect.timeoutOption(Duration.millis(RELAY_HOOK_UPSTREAM_TIMEOUT_MS)),
      Effect.result,
    );
    if (Result.isFailure(upstream)) {
      yield* outcome("environment_unavailable");
      return errorResponse(503, "environment_unavailable");
    }
    if (Option.isNone(upstream.success)) {
      yield* outcome("environment_timeout");
      return errorResponse(504, "environment_timeout");
    }
    const response = upstream.success.value;
    if (response.status === TUNNEL_OFFLINE_STATUS) {
      yield* outcome("environment_unavailable");
      return errorResponse(503, "environment_unavailable");
    }
    yield* Effect.annotateCurrentSpan({
      "relay.hook.outcome": "forwarded",
      "relay.hook.upstream_status": response.status,
    });
    // Only content-type is passed through: no location (redirects are never
    // followed or relayed), no cookies, no upstream infrastructure headers.
    const contentTypeHeaders = response.contentType
      ? { "content-type": response.contentType }
      : undefined;
    if (response.body.length === 0) {
      return HttpServerResponse.empty({
        status: response.status,
        ...(contentTypeHeaders ? { headers: contentTypeHeaders } : {}),
      });
    }
    return HttpServerResponse.uint8Array(response.body, {
      status: response.status,
      ...(response.contentType ? { contentType: response.contentType } : {}),
    });
  });

  return HookForwarder.of({ handle });
});

export const layer = Layer.effect(HookForwarder, make);

/** Registers the public hook forwarding route; static prefix outranks the `/*` fallback. */
export const relayHookRoute = HttpRouter.use((router) =>
  Effect.gen(function* () {
    const forwarder = yield* HookForwarder;
    yield* router.add("*", RELAY_HOOK_ROUTE, forwarder.handle);
  }),
);
