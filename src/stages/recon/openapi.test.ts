import { describe, test, expect } from "vitest";
import { parseOpenApiSpec } from "./openapi.js";

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
});
