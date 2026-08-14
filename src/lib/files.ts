import { readFile, stat } from "node:fs/promises";

/**
 * Read a file only if it exists and is non-empty; otherwise return null.
 * Used for partial-capture: after a scanner is killed, read whatever it managed
 * to write to disk without throwing on a missing/zero-byte file.
 */
export async function readFileIfNonEmpty(path: string): Promise<string | null> {
  try {
    const s = await stat(path);
    if (!s.isFile() || s.size === 0) return null;
    const content = await readFile(path, "utf8");
    return content.length > 0 ? content : null;
  } catch {
    return null;
  }
}

/** True if a file exists and has content. */
export async function fileHasContent(path: string): Promise<boolean> {
  return (await readFileIfNonEmpty(path)) !== null;
}
