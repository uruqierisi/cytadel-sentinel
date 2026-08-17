import { describe, test, expect } from "vitest";
import { hasInjectionPayload, normalizeParamValues, cleanParamUrls } from "./paramClean.js";
import { dedupeParamSignatures, paramSignature } from "../scan/params.js";

const HOST = "http://testasp.vulnweb.com";

// The exact wayback-poisoned URL from the destructive run, URL-encoded the way an
// archive stores it (decoded it reads:
//   /Login.asp?RetURL=/showforum.asp?id=1&XNYy=3116 AND 1=1 UNION ALL SELECT ...
//   EXEC xp_cmdshell('cat ../../../etc/passwd')#)
const POISONED =
  `${HOST}/Login.asp?RetURL=%2Fshowforum.asp%3Fid%3D1` +
  `&XNYy=3116%20AND%201%3D1%20UNION%20ALL%20SELECT%20NULL%2CNULL%20FROM%20information_schema.tables%3B` +
  `%20EXEC%20xp_cmdshell(%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27)%23`;

describe("hasInjectionPayload — reject archived attack strings in param values", () => {
  test("drops the decoded UNION / xp_cmdshell wayback URL", () => {
    expect(hasInjectionPayload(POISONED)).toBe(true);
  });

  test("also fires on the literal (already-decoded) form", () => {
    const decoded = `${HOST}/Login.asp?XNYy=3116 AND 1=1 UNION ALL SELECT NULL FROM information_schema.tables`;
    expect(hasInjectionPayload(decoded)).toBe(true);
  });

  const XSS = `${HOST}/Search.asp?tfSearch=%3Cscript%3Ealert(1)%3C%2Fscript%3E`;
  const TRAVERSAL = `${HOST}/download.asp?file=..%2F..%2F..%2Fetc%2Fpasswd`;
  const SQL_COMMENT = `${HOST}/p.asp?id=1'--+`;
  for (const [label, url] of [
    ["XSS <script>", XSS],
    ["path traversal", TRAVERSAL],
    ["SQL comment", SQL_COMMENT],
  ] as const) {
    test(`drops ${label}`, () => {
      expect(hasInjectionPayload(url)).toBe(true);
    });
  }

  test("keeps ordinary values (no false positives)", () => {
    expect(hasInjectionPayload(`${HOST}/showforum.asp?id=1`)).toBe(false);
    expect(hasInjectionPayload(`${HOST}/Search.asp?tfSearch=laptop`)).toBe(false);
    expect(hasInjectionPayload(`${HOST}/list.asp?cat=books&page=3`)).toBe(false);
    expect(hasInjectionPayload(`${HOST}/x.asp?token=aGVsbG8-d29ybGQ`)).toBe(false); // url-safe base64
  });
});

describe("normalizeParamValues — clean representative", () => {
  test("rewrites values to the neutral placeholder, keeps path + names + order", () => {
    expect(normalizeParamValues(`${HOST}/showforum.asp?id=99999`)).toBe(`${HOST}/showforum.asp?id=1`);
    expect(normalizeParamValues(`${HOST}/p.asp?b=x&a=y#frag`)).toBe(`${HOST}/p.asp?b=1&a=1`);
  });
});

describe("cleanParamUrls — drop payloads, normalize, dedupe (before signature dedupe)", () => {
  test("poisoned URL dropped; real params survive with clean values", () => {
    const raw = [
      POISONED,
      `${HOST}/showforum.asp?id=1`,
      `${HOST}/showforum.asp?id=99`, // same signature -> collapses after normalize
      `${HOST}/Search.asp?tfSearch=%3Cscript%3Ealert(1)%3C%2Fscript%3E`, // poisoned XSS value -> dropped
      `${HOST}/Search.asp?tfSearch=laptop`, // clean -> keeps the tfSearch signature
    ];
    const { urls, stats } = cleanParamUrls(raw);

    expect(stats.droppedPayload).toBe(2); // Login.asp poison + Search.asp XSS value
    // showforum.asp?id=1 and Search.asp?tfSearch=1 (deduped, normalized).
    expect(urls).toContain(`${HOST}/showforum.asp?id=1`);
    expect(urls).toContain(`${HOST}/Search.asp?tfSearch=1`);
    // No attack strings remain.
    expect(urls.every((u) => !hasInjectionPayload(u))).toBe(true);
  });

  test("deduped signatures INCLUDE showforum.asp?id= (value id=1) and Search.asp?tfSearch=", () => {
    const raw = [
      POISONED,
      ...Array.from({ length: 120 }, (_, i) => `${HOST}/showforum.asp?id=${i}`),
      `${HOST}/Search.asp?tfSearch=widget`,
    ];
    const { urls } = cleanParamUrls(raw);
    const signatures = dedupeParamSignatures(urls, 25);

    // The clean showforum representative reaches sqlmap with a working value.
    const forum = signatures.find((u) => /showforum\.asp\?id=/i.test(u));
    expect(forum).toBe(`${HOST}/showforum.asp?id=1`);
    expect(paramSignature(forum!)).toBe(`http://testasp.vulnweb.com/showforum.asp?id`);

    // The tfSearch XSS target reaches dalfox.
    expect(signatures.some((u) => /Search\.asp\?tfSearch=1$/i.test(u))).toBe(true);
  });
});
