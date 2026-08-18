import { describe, test, expect, vi } from "vitest";
vi.mock("../../lib/audit.js", () => ({ audit: vi.fn() }));
import { parseOpenApiSpec, discoverOpenApi } from "./openapi.js";
import { ScopeSchema } from "../../config/schema.js";
import { resolveAuth } from "../../config/auth.js";
import type { RunContext } from "../../core/context.js";
import type { HttpResponse } from "../../lib/http.js";

const SPEC_URL = "http://127.0.0.1:3000/openapi.json";

describe("parseOpenApiSpec — OpenAPI 3 + Swagger 2 (WP2)", () => {
  test("OpenAPI 3: query GET with example + POST requestBody with example values", () => {
    const spec = {
      openapi: "3.0.1",
      servers: [{ url: "/api" }],
      paths: {
        "/products/search": {
          get: {
            parameters: [{ name: "q", in: "query", schema: { type: "string", example: "apple" } }],
          },
        },
        "/user/login": {
          post: {
            requestBody: {
              content: {
                "application/json": {
                  schema: {
                    properties: { email: { type: "string", example: "a@b.c" }, password: { type: "string" } },
                  },
                },
              },
            },
          },
        },
      },
    };
    const cands = parseOpenApiSpec(spec, SPEC_URL);

    const get = cands.find((c) => c.method === "GET");
    expect(get!.url).toBe("http://127.0.0.1:3000/api/products/search?q=apple"); // real example value, not "1"
    expect(get!.paramNames).toContain("q");

    const post = cands.find((c) => c.method === "POST");
    expect(post!.url).toBe("http://127.0.0.1:3000/api/user/login");
    expect(post!.contentType).toBe("application/json");
    expect(JSON.parse(post!.body!)).toMatchObject({ email: "a@b.c", password: "test" });
    expect(post!.paramNames).toEqual(expect.arrayContaining(["email", "password"]));
  });

  test("Swagger 2: basePath + path param substitution + query example", () => {
    const spec = {
      swagger: "2.0",
      basePath: "/v2",
      paths: {
        "/store/order/{orderId}": {
          get: {
            parameters: [
              { name: "orderId", in: "path", type: "integer", default: 7 },
              { name: "verbose", in: "query", type: "boolean" },
            ],
          },
        },
      },
    };
    const cands = parseOpenApiSpec(spec, SPEC_URL);
    expect(cands.length).toBe(1);
    expect(cands[0]!.url).toBe("http://127.0.0.1:3000/v2/store/order/7?verbose=true");
  });

  test("operations with no fuzzable params are skipped", () => {
    const spec = { openapi: "3.0.0", paths: { "/health": { get: {} } } };
    expect(parseOpenApiSpec(spec, SPEC_URL)).toEqual([]);
  });

  test("Swagger 2.0 with $ref parameters resolves them (Juice-Shop shape)", () => {
    const spec = {
      swagger: "2.0",
      parameters: {
        SearchQuery: { name: "q", in: "query", type: "string", default: "apple" },
      },
      paths: {
        "/rest/products/search": {
          get: { parameters: [{ $ref: "#/parameters/SearchQuery" }] },
        },
      },
    };
    const cands = parseOpenApiSpec(spec, SPEC_URL);
    expect(cands.length).toBe(1);
    expect(cands[0]!.url).toBe("http://127.0.0.1:3000/rest/products/search?q=apple");
    expect(cands[0]!.paramNames).toEqual(["q"]);
  });

  test("OpenAPI 3 requestBody via $ref schema resolves body params", () => {
    const spec = {
      openapi: "3.0.0",
      components: { schemas: { Login: { properties: { email: { type: "string", example: "a@b.c" }, password: { type: "string" } } } } },
      paths: {
        "/rest/user/login": {
          post: { requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/Login" } } } } },
        },
      },
    };
    const cands = parseOpenApiSpec(spec, SPEC_URL);
    expect(cands.length).toBe(1);
    expect(JSON.parse(cands[0]!.body!)).toMatchObject({ email: "a@b.c", password: "test" });
  });
});

describe("discoverOpenApi — live probe (auto-probe common locations)", () => {
  const noopLog = { info() {}, warn() {}, error() {}, debug() {}, child() { return noopLog; } } as unknown as RunContext["log"];
  function ctxFor(): RunContext {
    const scope = ScopeSchema.parse({ name: "js", authorized_by: "me", authorization_ref: "L", in_scope: { domains: ["127.0.0.1"] } });
    return { runId: "r", actor: "t", scopeHash: "h", scope, auth: resolveAuth(scope), log: noopLog } as unknown as RunContext;
  }
  const res = (status: number, body: string): HttpResponse => ({ status, headers: {}, body, truncated: false, durationMs: 1, requestLine: "GET" });

  test("Juice-Shop-style: /swagger.json 200 (large spec) is probed and its endpoints enter the set", async () => {
    const spec = {
      openapi: "3.0.0",
      paths: { "/rest/products/search": { get: { parameters: [{ name: "q", in: "query", schema: { type: "string", example: "apple" } }] } } },
    };
    const http = vi.fn(async (url: string) =>
      url === "http://127.0.0.1:3000/swagger.json" ? res(200, JSON.stringify(spec)) : res(404, "not found"),
    );
    const { candidates } = await discoverOpenApi(ctxFor(), ["http://127.0.0.1:3000"], [], http);
    expect(candidates.length).toBe(1);
    expect(candidates[0]!.url).toBe("http://127.0.0.1:3000/rest/products/search?q=apple");
    // It actually probed /swagger.json among the common locations.
    expect(http.mock.calls.some((c) => c[0] === "http://127.0.0.1:3000/swagger.json")).toBe(true);
  });

  test("a 200 that is not JSON surfaces a coverage note (never a silent 0)", async () => {
    const http = vi.fn(async (url: string) =>
      url.endsWith("/api-docs") ? res(200, "<html>swagger ui</html>") : res(404, ""),
    );
    const { candidates, notes } = await discoverOpenApi(ctxFor(), ["http://127.0.0.1:3000"], [], http);
    expect(candidates).toEqual([]);
    // The repeated non-JSON probes collapse into ONE coverage note.
    expect(notes.length).toBe(1);
    expect(notes[0]).toMatch(/not exposed as JSON/);
    expect(notes[0]).toMatch(/returned non-JSON/);
  });
});
