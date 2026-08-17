import { describe, test, expect } from "vitest";
import { isProjectDiscoveryHttpx } from "./toolResolver.js";

describe("isProjectDiscoveryHttpx — tell the PD build from the Python one", () => {
  const PD_OUTPUTS = [
    "[INF] Current httpx version v1.6.9 (latest)",
    "httpx version v1.3.7",
    "Projectdiscovery.io httpx v1.2.0",
    "v1.6.9",
  ];
  for (const out of PD_OUTPUTS) {
    test(`accepts PD banner: "${out}"`, () => {
      expect(isProjectDiscoveryHttpx(out)).toBe(true);
    });
  }

  const NON_PD_OUTPUTS = [
    // Python httpx CLI: bare semver, no leading 'v', no PD banner.
    "0.27.0",
    "httpx, version 0.27.0",
    // Python click error when it can't parse `-version`.
    "Error: No such option: -v",
    "Usage: httpx [OPTIONS] URL",
    // Nothing at all.
    "",
    "   \n  ",
  ];
  for (const out of NON_PD_OUTPUTS) {
    test(`rejects non-PD output: ${JSON.stringify(out)}`, () => {
      expect(isProjectDiscoveryHttpx(out)).toBe(false);
    });
  }
});
