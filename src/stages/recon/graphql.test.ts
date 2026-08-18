import { describe, test, expect } from "vitest";
import { parseIntrospection, graphqlCandidates } from "./graphql.js";

describe("GraphQL introspection parsing (WP2)", () => {
  const introspection = {
    data: {
      __schema: {
        queryType: { name: "Query" },
        mutationType: { name: "Mutation" },
        types: [
          {
            name: "Query",
            fields: [
              { name: "productById", args: [{ name: "id" }] },
              { name: "searchProducts", args: [{ name: "query" }] },
              { name: "me", args: [] },
            ],
          },
          {
            name: "Mutation",
            fields: [{ name: "login", args: [{ name: "email" }, { name: "password" }] }],
          },
        ],
      },
    },
  };

  test("derives query + mutation fields with their argument names", () => {
    const { queries, mutations } = parseIntrospection(introspection);
    expect(queries.map((f) => f.name)).toEqual(expect.arrayContaining(["productById", "searchProducts", "me"]));
    expect(queries.find((f) => f.name === "productById")!.args).toEqual(["id"]);
    expect(mutations.find((f) => f.name === "login")!.args).toEqual(["email", "password"]);
  });

  test("builds POST candidates fuzzing an argument (fields without args skipped)", () => {
    const { queries } = parseIntrospection(introspection);
    const cands = graphqlCandidates("http://127.0.0.1:3000/graphql", queries, "query");
    expect(cands.length).toBe(2); // productById + searchProducts (me has no args)
    for (const c of cands) {
      expect(c.method).toBe("POST");
      expect(c.contentType).toBe("application/json");
      expect(c.source).toBe("graphql");
      expect(c.url).toBe("http://127.0.0.1:3000/graphql");
      expect(JSON.parse(c.body!).query).toContain("__typename");
    }
    expect(cands[0]!.paramNames).toEqual(["id"]);
  });

  test("disabled introspection => no fields", () => {
    expect(parseIntrospection({ errors: [{ message: "introspection disabled" }] })).toEqual({ queries: [], mutations: [] });
  });
});
