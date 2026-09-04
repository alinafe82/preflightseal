import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { stableStringify } from "./json.ts";

export function sha256Bytes(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function sha256File(path: string): Promise<string> {
  return sha256Bytes(await readFile(path));
}

export function sha256Json(value: unknown): string {
  return sha256Bytes(stableStringify(value));
}
