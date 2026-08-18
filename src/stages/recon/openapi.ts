import { httpRequest, type HttpResponse } from "../../lib/http.js";
import { gate, type RunContext } from "../../core/context.js";
import type { HttpFn } from "./jsAnalyze.js";
import type { HttpMethodU, InjectionCandidate } from "../scan/candidates.js";

/**
 * OpenAPI / Swagger import (WP2, task 2).
 *
 * Probes scope-provided and common spec locations, parses Swagger 2.0 and
 * OpenAPI 3.x into CONCRETE endpoints — method + real example values for query
 * params and (for POST/PUT/PATCH) a body template — and hands them to the
 * injection candidate set. Example values come from the spec (never normalized
 * to "1"), so blind-injection detection has a working request.
 *
 * Parsing is pure (unit-testable). Every produced URL is scope-gated by the
 * caller before use.
 */

export const COMMON_SPEC_PATHS: readonly string[] = [
  "/swagger.json",
  "/openapi.json",
  "/api-docs",
  "/v3/api-docs",
  "/swagger/v1/swagger.json",
  "/api/swagger.json",
];

const INJECT_METHODS: ReadonlySet<string> = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

type AnyObj = Record<string, unknown>;
const obj = (v: unknown): AnyObj => (v && typeof v === "object" ? (v as AnyObj) : {});
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

/** Resolve a local "#/…" JSON-Pointer $ref within the root doc (one hop). */
function deref(node: AnyObj, root: AnyObj): AnyObj {
  const ref = str(node["$ref"]);
  if (!ref || !ref.startsWith("#/")) return node;
  let cur: unknown = root;
  for (const seg of ref.slice(2).split("/")) {
    cur = obj(cur)[seg.replace(/~1/g, "/").replace(/~0/g, "~")];
  }
  return obj(cur);
}

export function specVersion(spec: unknown): string {
  const d = obj(spec);
  if (str(d["openapi"])) return `openapi ${str(d["openapi"])}`;
  if (str(d["swagger"])) return `swagger ${str(d["swagger"])}`;
  return "unknown";
}

export function pathCount(spec: unknown): number {
  return Object.keys(obj(obj(spec)["paths"])).length;
}

/** A concrete example value for a parameter/schema, preferring spec-provided ones. */
function exampleValue(schemaLike: AnyObj, root: AnyObj): string {
  const schema = deref(obj(schemaLike["schema"]), root);
  const example = schemaLike["example"] ?? schemaLike["default"] ?? schema["example"] ?? schema["default"];
  if (example !== undefined && example !== null && typeof example !== "object") return String(example);
  const type = str(schemaLike["type"]) ?? str(schema["type"]) ?? "string";
  if (type === "integer" || type === "number") return "1";
  if (type === "boolean") return "true";
  return "test";
}

/** Build a JSON/form body from a schema's properties (OpenAPI 3 requestBody / Swagger body). */
function bodyFromSchema(schemaNode: AnyObj, root: AnyObj): { names: string[]; json: Record<string, string> } {
  const schema = deref(schemaNode, root);
  const props = obj(schema["properties"]);
  const names = Object.keys(props);
  const json: Record<string, string> = {};
  for (const n of names) json[n] = exampleValue(deref(obj(props[n]), root), root);
  return { names, json };
}

function substitutePathParams(path: string, values: Record<string, string>): string {
  return path
    .replace(/\{([^}]+)\}/g, (_, n: string) => values[n] ?? "1") // OpenAPI {id}
    .replace(/:([A-Za-z0-9_]+)/g, (_, n: string) => values[n] ?? "1"); // Express :id
}

/**
 * Parse a spec document into concrete injection candidates. `specUrl` fixes the
 * origin the endpoints resolve against.
 */
export function parseOpenApiSpec(spec: unknown, specUrl: string): InjectionCandidate[] {
  const doc = obj(spec);
  const paths = obj(doc["paths"]);
  if (Object.keys(paths).length === 0) return [];

  let origin: string;
  try {
    const su = new URL(specUrl);
    origin = `${su.protocol}//${su.host}`;
  } catch {
    return [];
  }

  let pathPrefix = "";
  if (str(doc["swagger"])?.startsWith("2")) {
    pathPrefix = str(doc["basePath"]) ?? "";
  } else if (str(doc["openapi"])?.startsWith("3")) {
    const server = str(obj((doc["servers"] as unknown[])?.[0])["url"]);
    if (server) {
      try {
        const su = new URL(server, origin);
        origin = `${su.protocol}//${su.host}`;
        pathPrefix = su.pathname.replace(/\/$/, "");
      } catch {
        /* keep origin */
      }
    }
  }

  const out: InjectionCandidate[] = [];
  for (const [rawPath, pathItemRaw] of Object.entries(paths)) {
    const pathItem = obj(pathItemRaw);
    const pathLevelParams = Array.isArray(pathItem["parameters"]) ? (pathItem["parameters"] as unknown[]) : [];
    for (const [methodRaw, opRaw] of Object.entries(pathItem)) {
      const method = methodRaw.toUpperCase();
      if (!INJECT_METHODS.has(method)) continue;
      const op = obj(opRaw);
      const params = [...pathLevelParams, ...(Array.isArray(op["parameters"]) ? (op["parameters"] as unknown[]) : [])].map(
        (p) => deref(obj(p), doc),
      );

      const pathValues: Record<string, string> = {};
      const query: Array<[string, string]> = [];
      const bodyNames: string[] = [];
      const bodyJson: Record<string, string> = {};

      for (const p of params) {
        const name = str(p["name"]);
        if (!name) continue;
        const where = str(p["in"]);
        if (where === "path") pathValues[name] = exampleValue(p, doc);
        else if (where === "query") query.push([name, exampleValue(p, doc)]);
        else if (where === "formData") { bodyNames.push(name); bodyJson[name] = exampleValue(p, doc); }
        else if (where === "body") {
          const b = bodyFromSchema(obj(p["schema"]), doc);
          bodyNames.push(...b.names);
          Object.assign(bodyJson, b.json);
        }
      }

      // OpenAPI 3 requestBody (may itself be a $ref).
      let contentType: string | null = null;
      const rbContent = obj(deref(obj(op["requestBody"]), doc)["content"]);
      if (rbContent["application/json"]) {
        contentType = "application/json";
        const b = bodyFromSchema(obj(obj(rbContent["application/json"])["schema"]), doc);
        bodyNames.push(...b.names);
        Object.assign(bodyJson, b.json);
      } else if (rbContent["application/x-www-form-urlencoded"]) {
        contentType = "application/x-www-form-urlencoded";
        const b = bodyFromSchema(obj(obj(rbContent["application/x-www-form-urlencoded"])["schema"]), doc);
        bodyNames.push(...b.names);
        Object.assign(bodyJson, b.json);
      }

      const concretePath = substitutePathParams(`${pathPrefix}${rawPath}`, pathValues);
      let url: string;
      try {
        const u = new URL(origin);
        u.pathname = concretePath;
        for (const [n, v] of query) u.searchParams.append(n, v);
        url = u.toString();
      } catch {
        continue;
      }

      const hasBody = bodyNames.length > 0;
      // Only inject where there's something to fuzz (query or body params).
      if (query.length === 0 && !hasBody) continue;

      let body: string | null = null;
      if (hasBody) {
        if (contentType === "application/x-www-form-urlencoded") {
          body = new URLSearchParams(bodyJson).toString();
        } else {
          contentType = contentType ?? "application/json";
          body = JSON.stringify(bodyJson);
        }
      }

      out.push({
        url,
        method: method as HttpMethodU,
        body,
        contentType,
        paramNames: [...query.map(([n]) => n), ...bodyNames],
        source: "openapi",
      });
    }
  }
  return out;
}

/** Specs can be large; the default 512 KiB body cap truncated them → parse fail. */
const MAX_SPEC_BYTES = 16 * 1024 * 1024;

/** Fetch + parse an OpenAPI/Swagger spec from candidate locations, gating each result. */
export async function discoverOpenApi(
  ctx: RunContext,
  baseOrigins: string[],
  explicitSpecUrls: string[],
  httpFn: HttpFn = httpRequest,
): Promise<{ candidates: InjectionCandidate[]; notes: string[] }> {
  const specUrls = new Set<string>(explicitSpecUrls);
  for (const origin of baseOrigins) {
    for (const p of COMMON_SPEC_PATHS) {
      try {
        specUrls.add(new URL(p, origin).toString());
      } catch {
        /* skip */
      }
    }
  }

  const candidates: InjectionCandidate[] = [];
  const notes: string[] = [];
  let probed = 0;
  let specsFound = 0;
  for (const specUrl of specUrls) {
    if (!(await gate(ctx, specUrl)).allowed) continue;
    probed++;
    let res: HttpResponse;
    try {
      res = await httpFn(specUrl, { headers: ctx.auth.headerMap, maxBodyBytes: MAX_SPEC_BYTES, maxRedirections: 3 });
    } catch (err) {
      // Distinct FETCH-RESULT line (separate from SCOPE_ACCEPT), always visible.
      ctx.log.warn({ specUrl, error: (err as Error).message }, "recon: FETCH OpenAPI spec FAILED");
      continue;
    }
    const contentType = res.headers["content-type"];
    ctx.log.info(
      { specUrl, status: res.status, bodyLen: res.body.length, contentType, truncated: res.truncated },
      "recon: FETCH OpenAPI spec",
    );
    if (res.status < 200 || res.status >= 300) continue;
    let spec: unknown;
    try {
      spec = JSON.parse(res.body);
    } catch (err) {
      ctx.log.warn(
        { specUrl, status: res.status, bodyLen: res.body.length, truncated: res.truncated, error: (err as Error).message },
        "recon: OpenAPI 200 but body is not JSON",
      );
      notes.push(`OpenAPI: ${specUrl} returned 200 but body was not valid JSON (${res.body.length} bytes${res.truncated ? ", TRUNCATED" : ""})`);
      continue;
    }
    const version = specVersion(spec);
    const parsed = parseOpenApiSpec(spec, specUrl);
    ctx.log.info(
      { specUrl, version, pathCount: pathCount(spec), endpoints: parsed.length },
      "recon: OpenAPI spec parsed",
    );
    if (parsed.length === 0) {
      notes.push(`OpenAPI: ${specUrl} parsed (${version}, ${pathCount(spec)} paths) but yielded 0 injectable endpoints`);
      continue;
    }
    specsFound++;
    for (const c of parsed) {
      if ((await gate(ctx, c.url)).allowed) candidates.push(c);
    }
  }
  ctx.log.info({ probed, specsFound, candidates: candidates.length }, "recon: OpenAPI discovery complete");
  if (specsFound === 0) notes.push(`OpenAPI: probed ${probed} location(s), no parseable spec found`);
  return { candidates, notes };
}
