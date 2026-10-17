/** Single-valued OAuth parameters. */
export type Params = Map<string, string>;

/**
 * URLSearchParams → Map, or null if any parameter is repeated (RFC 6749 § 3.1 / § 3.2: request
 * parameters MUST NOT be included more than once). A Map, not an object: no `__proto__` surprises.
 */
export function readParams(sp: URLSearchParams): Params | null {
  const out: Params = new Map();
  for (const [k, v] of sp) {
    if (out.has(k)) return null;
    out.set(k, v);
  }
  return out;
}
