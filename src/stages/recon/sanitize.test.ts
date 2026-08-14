import { describe, test, expect } from "vitest";
import { sanitizeUrl, sanitizeDiscoveredUrls, capEndpointsPerHost } from "./sanitize.js";

const TARGET = "testasp.vulnweb.com";
const isInScopeHost = (host: string) => host === TARGET || host.endsWith("." + TARGET);

describe("sanitizeUrl — mangled external URLs from the live run", () => {
  // The exact shapes that inflated assets to 1020 and made nuclei take 30 min.
  const MANGLED = [
    "testasp.vulnweb.com:/www.amazon.com/dp/B00005N5PF",
    "testasp.vulnweb.com:/www.nfl.com/news/story/09000d5d82476a29",
  ];

  for (const raw of MANGLED) {
    test(`drops "${raw}"`, () => {
      const res = sanitizeUrl(raw, isInScopeHost);
      expect(res.url).toBeNull();
      expect(res.reason).toBe("external-host");
    });
  }

  test("drops the same mangle without the empty-port colon", () => {
    const res = sanitizeUrl("testasp.vulnweb.com/www.amazon.com/dp/X", isInScopeHost);
    expect(res.url).toBeNull();
    expect(res.reason).toBe("external-host");
  });

  test("drops a bare external registrable domain in the path (no www.)", () => {
    const res = sanitizeUrl("testasp.vulnweb.com/amazon.com/dp/X", isInScopeHost);
    expect(res.url).toBeNull();
    expect(res.reason).toBe("external-host");
  });

  test("drops URLs whose path/query embeds a scheme", () => {
    const res = sanitizeUrl("http://testasp.vulnweb.com/redir.aspx?url=http://www.evil.com/x", isInScopeHost);
    expect(res.url).toBeNull();
    expect(res.reason).toBe("embedded-scheme");
  });
});

describe("sanitizeUrl — normalization of malformed host:/path", () => {
  test('normalizes empty-port "host:/path" to "host/path"', () => {
    const res = sanitizeUrl("testasp.vulnweb.com:/admin/login.asp", isInScopeHost);
    expect(res.reason).toBe("normalized");
    expect(res.url).toBe("testasp.vulnweb.com/admin/login.asp");
  });

  test("preserves scheme + query while normalizing", () => {
    const res = sanitizeUrl("http://testasp.vulnweb.com:/Templatize.asp?item=2", isInScopeHost);
    expect(res.reason).toBe("normalized");
    expect(res.url).toBe("http://testasp.vulnweb.com/Templatize.asp?item=2");
  });
});

describe("sanitizeUrl — legitimate in-scope URLs are kept", () => {
  const KEEP = [
    "http://testasp.vulnweb.com/Default.asp",
    "http://testasp.vulnweb.com/sitemap.xml",
    "http://testasp.vulnweb.com/Templatize.asp?item=2&cat=1",
    "testasp.vulnweb.com/Search.asp?tfSearch=x",
    "http://testasp.vulnweb.com/styles/app.css",
  ];
  for (const raw of KEEP) {
    test(`keeps "${raw}"`, () => {
      const res = sanitizeUrl(raw, isInScopeHost);
      expect(res.url).not.toBeNull();
      expect(res.reason).toBe("kept");
    });
  }

  test("keeps an in-scope subdomain appearing as a leading path segment", () => {
    const res = sanitizeUrl("testasp.vulnweb.com/api.testasp.vulnweb.com/v1", isInScopeHost);
    expect(res.url).not.toBeNull();
  });

  test("empty / unparseable inputs are dropped", () => {
    expect(sanitizeUrl("", isInScopeHost).url).toBeNull();
    expect(sanitizeUrl("   ", isInScopeHost).url).toBeNull();
  });
});

describe("sanitizeDiscoveredUrls — batch stats + dedupe", () => {
  test("dedupes and classifies a mixed batch", () => {
    const raw = [
      "testasp.vulnweb.com:/www.amazon.com/dp/B00005N5PF", // external
      "testasp.vulnweb.com:/www.nfl.com/news/story/1", // external
      "http://testasp.vulnweb.com/Default.asp", // keep
      "http://testasp.vulnweb.com/Default.asp", // dup
      "http://testasp.vulnweb.com/redir?u=http://x.com", // embedded scheme
      "testasp.vulnweb.com:/admin/login.asp", // normalized keep
    ];
    const { urls, stats } = sanitizeDiscoveredUrls(raw, isInScopeHost);
    expect(stats.total).toBe(6);
    expect(stats.droppedExternalHost).toBe(2);
    expect(stats.droppedEmbeddedScheme).toBe(1);
    expect(stats.duplicates).toBe(1);
    expect(stats.normalized).toBe(1);
    expect(stats.kept).toBe(2);
    expect(urls).toContain("http://testasp.vulnweb.com/Default.asp");
    expect(urls).toContain("testasp.vulnweb.com/admin/login.asp");
  });
});

describe("capEndpointsPerHost", () => {
  test("caps per host and reports the dropped count", () => {
    const urls = Array.from({ length: 10 }, (_, i) => `http://testasp.vulnweb.com/p${i}`);
    urls.push("http://other.testasp.vulnweb.com/only");
    const { kept, truncated } = capEndpointsPerHost(urls, 4);
    expect(kept.filter((u) => u.includes("//testasp.vulnweb.com/")).length).toBe(4);
    expect(truncated.get("testasp.vulnweb.com")).toBe(6);
    expect(truncated.has("other.testasp.vulnweb.com")).toBe(false);
  });
});
