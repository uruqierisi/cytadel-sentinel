import { describe, test, expect } from "vitest";
import { extractInjectionsFromSessionText } from "./sqlmapSession.js";

/**
 * A representative decoded session.sqlite `storage` blob. sqlmap serializes the
 * confirmed injections; the technique titles, payloads and DBMS survive as
 * readable ASCII substrings within the (binary) pickle, which is what the
 * fallback scrapes. This mimics that: readable markers embedded in noise.
 */
const SESSION_BLOB =
  "\x80\x04\x95...q\x94...place\x94GET\x94parameter\x94q\x94" +
  "boolean-based blind\x94title OR boolean-based blind - WHERE or HAVING clause (NOT)" +
  "\x94payload q=apple%' OR NOT 6539=6539-- pMDU\x94" +
  "time-based blind\x94SQLite > 2.0 AND time-based blind (heavy query)" +
  "\x94payload q=apple%' AND 1234=LIKE(CHAR(65),UPPER(HEX(RANDOMBLOB(500000000))))-- FdyY\x94" +
  "back-end DBMS SQLite\x94";

const URL = "http://127.0.0.1:3000/rest/products/search?q=apple";

describe("extractInjectionsFromSessionText — session.sqlite fallback", () => {
  test("recovers boolean + time-based findings on param q with payloads and DBMS", () => {
    const findings = extractInjectionsFromSessionText(SESSION_BLOB, URL);
    expect(findings.length).toBe(2);
    const titles = findings.map((f) => f.title).join(" | ");
    expect(titles).toContain("boolean-based blind");
    expect(titles).toContain("time-based blind");
    for (const f of findings) {
      expect(f.sourceTool).toBe("sqlmap");
      expect(f.severity).toBe("HIGH");
      expect(f.endpoint).toBe(URL);
      expect(f.title).toContain('parameter "q"'); // derived from the URL query name
      expect(f.title).not.toContain('parameter ""');
      expect(f.evidence).toContain("q=apple"); // scraped payload
      expect(f.evidence).toContain("DBMS: SQLite");
    }
  });

  test("empty / non-injection blob yields nothing", () => {
    expect(extractInjectionsFromSessionText("", URL)).toEqual([]);
    expect(extractInjectionsFromSessionText("just some warnings, no injection here", URL)).toEqual([]);
  });
});
