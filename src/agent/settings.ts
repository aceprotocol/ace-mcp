import {
  ACEError, canonicalStateBytes, sha256Hex, validateCard,
  type ACEStore, type AgentCard, type DescriptorDelegation, type Erc8004Binding, type JSONObject, type ProfileManifest, type Visibility,
} from '@ace-protocol/sdk';

/** The reserved card tag: this service holds the identity's keys. */
export const HOSTED_TAG = 'hosted';
export const BUNDLED_PROFILES = ['text', 'commerce'] as const;
export type BundledProfile = (typeof BUNDLED_PROFILES)[number];

/**
 * One hosted identity's local policy and published claims. Only the owner (or a client holding `ace:configure`)
 * changes it; a remote message never does. Saved sealed in the identity's store, and only after the SDK published a
 * descriptor built from it (the SDK's descriptor rules are the one validation).
 */
export interface HostedSettings {
  visibility: Visibility;
  handle?: string;
  card: AgentCard;
  /** Installed official profiles. */
  profiles: BundledProfile[];
  /** Installed third-party profile manifests (data-only vocabularies). */
  manifests: ProfileManifest[];
  /** Profiles whose contact requests are accepted without an explicit accept. */
  acceptProfiles: string[];
  /** Descriptor `ext`, keyed by installed profile id. */
  ext?: Record<string, JSONObject>;
  /** Delegation credentials naming this identity as subject, each with its issuer's KEL. */
  delegations: DescriptorDelegation[];
  erc8004: Erc8004Binding[];
}

const KEY = 'mcp/settings.json';

const bad = (message: string) => new ACEError('invalid_argument', message);

/** The card with the `hosted` tag forced (at most 10 tags in total). */
export function hostedCard(card: unknown): AgentCard {
  const c = validateCard(card);
  const tags = [...new Set([...(c.tags ?? []), HOSTED_TAG])];
  if (tags.length > 10) throw bad(`card: at most 9 tags plus "${HOSTED_TAG}"`);
  return validateCard({ ...c, tags });
}

export function defaultSettings(name: string): HostedSettings {
  return { visibility: 'private', card: hostedCard({ name }), profiles: ['text'], manifests: [], acceptProfiles: [], delegations: [], erc8004: [] };
}

export async function loadSettings(store: ACEStore): Promise<HostedSettings | null> {
  const raw = await store.read(KEY);
  return raw === null ? null : JSON.parse(new TextDecoder().decode(raw)) as HostedSettings;
}

export async function saveSettings(store: ACEStore, s: HostedSettings): Promise<void> {
  await store.write(KEY, canonicalStateBytes(s));
}

export function settingsDigest(s: HostedSettings | null): string {
  return s === null ? '' : sha256Hex(canonicalStateBytes(s));
}
