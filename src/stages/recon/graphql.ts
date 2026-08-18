import { httpRequest, type HttpResponse } from "../../lib/http.js";
import { gate, type RunContext } from "../../core/context.js";
import type { HttpFn } from "./jsAnalyze.js";
import type { InjectionCandidate } from "../scan/candidates.js";

/**
 * GraphQL discovery (WP2, task 3).
 *
 * When a /graphql endpoint exists we attempt introspection; if enabled, we
 * derive query/mutation fields + their argument names as testable inputs
 * (POST candidates with a query-body template). If introspection is disabled we
 * record that in coverage rather than silently skipping.
 *
 * Parsing is pure/testable. Endpoints and candidate URLs are scope-gated.
 */

export const COMMON_GRAPHQL_PATHS: readonly string[] = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];

const INTROSPECTION_QUERY =
  "query IntrospectionQuery { __schema { queryType { name } mutationType { name } " +
  "types { name kind fields { name args { name type { name kind ofType { name } } } } } } }";

export interface GraphqlField {
  name: string;
  args: string[];
}

type AnyObj = Record<string, unknown>;
const obj = (v: unknown): AnyObj => (v && typeof v === "object" ? (v as AnyObj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

/** Parse an introspection response into query + mutation fields with arg names. */
export function parseIntrospection(introspectionJson: unknown): { queries: GraphqlField[]; mutations: GraphqlField[] } {
  const schema = obj(obj(obj(introspectionJson)["data"])["__schema"]);
  if (Object.keys(schema).length === 0) return { queries: [], mutations: [] };
  const queryTypeName = str(obj(schema["queryType"])["name"]);
  const mutationTypeName = str(obj(schema["mutationType"])["name"]);
  const types = arr(schema["types"]).map(obj);

  const fieldsOf = (typeName: string | null): GraphqlField[] => {
    if (!typeName) return [];
    const t = types.find((x) => str(x["name"]) === typeName);
    if (!t) return [];
    return arr(t["fields"])
      .map(obj)
      .map((f) => ({
        name: str(f["name"]) ?? "",
        args: arr(f["args"]).map(obj).map((a) => str(a["name"]) ?? "").filter(Boolean),
      }))
      .filter((f) => f.name.length > 0);
  };

  return { queries: fieldsOf(queryTypeName), mutations: fieldsOf(mutationTypeName) };
}

/** Build POST injection candidates that fuzz one argument of each field. */
export function graphqlCandidates(endpoint: string, fields: GraphqlField[], opType: "query" | "mutation", cap = 25): InjectionCandidate[] {
  const out: InjectionCandidate[] = [];
  for (const f of fields) {
    if (f.args.length === 0) continue;
    const arg = f.args[0]!;
    // Best-effort operation body; __typename is a universally valid selection.
    const query = `${opType} { ${f.name}(${arg}: "FUZZ") { __typename } }`;
    out.push({
      url: endpoint,
      method: "POST",
      body: JSON.stringify({ query }),
      contentType: "application/json",
      paramNames: [arg],
      source: "graphql",
    });
    if (out.length >= cap) break;
  }
  return out;
}

export interface GraphqlDiscovery {
  candidates: InjectionCandidate[];
  /** Coverage note, e.g. "GraphQL introspection disabled at /graphql". */
  notes: string[];
}

/** Probe for GraphQL endpoints, introspect when possible, and derive candidates. */
export async function discoverGraphql(
  ctx: RunContext,
  baseOrigins: string[],
  knownEndpoints: string[],
  httpFn: HttpFn = httpRequest,
): Promise<GraphqlDiscovery> {
  const endpoints = new Set<string>();
  for (const e of knownEndpoints) if (/\/graphql\b/i.test(e)) endpoints.add(e);
  for (const origin of baseOrigins) {
    for (const p of COMMON_GRAPHQL_PATHS) {
      try {
        endpoints.add(new URL(p, origin).toString());
      } catch {
        /* skip */
      }
    }
  }

  const candidates: InjectionCandidate[] = [];
  const notes: string[] = [];
  for (const endpoint of endpoints) {
    if (!(await gate(ctx, endpoint)).allowed) continue;
    let res: HttpResponse;
    try {
      res = await httpFn(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", ...ctx.auth.headerMap },
        body: JSON.stringify({ query: INTROSPECTION_QUERY }),
      });
    } catch {
      continue;
    }
    if (res.status < 200 || res.status >= 300) continue;

    let json: unknown;
    try {
      json = JSON.parse(res.body);
    } catch {
      continue;
    }
    const { queries, mutations } = parseIntrospection(json);
    if (queries.length === 0 && mutations.length === 0) {
      notes.push(`GraphQL endpoint ${endpoint}: introspection disabled or empty (not tested)`);
      ctx.log.info({ endpoint }, "recon: GraphQL introspection disabled/empty");
      continue;
    }
    const built = [
      ...graphqlCandidates(endpoint, queries, "query"),
      ...graphqlCandidates(endpoint, mutations, "mutation"),
    ];
    for (const c of built) {
      if ((await gate(ctx, c.url)).allowed) candidates.push(c);
    }
    ctx.log.info({ endpoint, queries: queries.length, mutations: mutations.length, candidates: built.length }, "recon: GraphQL introspection parsed");
  }
  return { candidates, notes };
}
