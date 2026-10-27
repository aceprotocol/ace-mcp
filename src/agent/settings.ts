import {
  ACEError, DELEGATION_PROFILE_ID, canonicalStateBytes, sha256Hex, validateCard,
  type ACEStore, type AgentCard, type Contact, type DelegationCredential, type Erc8004Binding, type JSONObject, type ProfileManifest,
} from '@ace-protocol/sdk';

/** The reserved card tag: this service holds the identity's keys. */
export const HOSTED_TAG = 'hosted';
export const BUNDLED_PROFILES = ['text', 'commerce', 'delegation'] as const;
export type BundledProfile = (typeof BUNDLED_PROFILES)[number];

/**
 * One hosted identity's local policy and published claims. Only the owner (or a client holding `ace:configure`)
 * changes it; a remote message never does. Saved sealed in the identity's store, and only after the SDK published the
 * descriptor and card record built from it (the SDK's rules and the relay are the one validation).
 */
export interface HostedSettings {
  /** Card record: the handle at the home relay. Set once: the relay refuses any other once it bound one. */
  handle?: string;
  /** Card record: the discovery card (description, image, tags; always carries the `hosted` tag). */
  card: AgentCard;
  /** Card record: CAIP-10 accounts this agent asks to be paid at. */
  pay?: string[];
  /** Card record: whether strangers' contact requests are processed. */
  contact: Contact;
  /** Card record: whether the home relay's directory lists this identity. */
  listed: boolean;
  /** Installed official profiles. */
  profiles: BundledProfile[];
  /** Installed third-party profile manifests (data-only vocabularies). */
  manifests: ProfileManifest[];
  /** Profiles whose contact requests are accepted without an explicit accept. */
  acceptProfiles: string[];
  /** Descriptor `ext`, keyed by installed profile id. */
  ext?: Record<string, JSONObject>;
  /**
   * `ace:delegation:1` credentials naming this identity as subject (one per issuer): the live ones are published in
   * the descriptor's `ext['ace:delegation:1']`, with the delegation profile installed whether or not `profiles` names it.
   */
  delegations: DelegationCredential[];
  /** Card record: ERC-8004 registrations of this agent (claimed, not proven). */
  erc8004: Erc8004Binding[];
}

const KEY = 'mcp/settings.json';

/** The credentials of `s` still live at `now` (an expired one is not published: its issuer stopped renewing). */
function liveDelegations(s: HostedSettings, now: number): DelegationCredential[] {
  return s.delegations.filter((d) => d.expiresAt > now);
}

/**
 * What `NetworkClient.open` publishes for `s` at `now` beyond the card record's own members: the descriptor `ext` (the
 * settings' `ext` plus `ace:delegation:1` holding the live credentials, when there are any) and the profiles to
 * install (the configured ones, plus the delegation profile while it publishes credentials; it can also be installed
 * on its own, to send or receive the `ace:delegation:1` hand-over message without credentials).
 */
export function publishedProfiles(s: HostedSettings, now: number): { profiles: Array<BundledProfile | ProfileManifest>; ext?: Record<string, JSONObject> } {
  const credentials = liveDelegations(s, now);
  const bundled = new Set<BundledProfile>(s.profiles);
  if (credentials.length) bundled.add('delegation');
  const profiles = [...bundled, ...s.manifests];
  if (!credentials.length) return { profiles, ...(s.ext ? { ext: s.ext } : {}) };
  return { profiles, ext: { ...s.ext, [DELEGATION_PROFILE_ID]: { credentials } as unknown as JSONObject } };
}

const bad = (message: string) => new ACEError('invalid_argument', message);

/** The card with the `hosted` tag forced (at most 10 tags in total). */
export function hostedCard(card: unknown): AgentCard {
  const c = validateCard(card);
  const tags = [...new Set([...(c.tags ?? []), HOSTED_TAG])];
  if (tags.length > 10) throw bad(`card: at most 9 tags plus "${HOSTED_TAG}"`);
  return validateCard({ ...c, tags });
}

export function defaultSettings(): HostedSettings {
  return { contact: 'closed', listed: false, card: hostedCard({}), profiles: ['text'], manifests: [], acceptProfiles: [], delegations: [], erc8004: [] };
}

/** The saved settings. */
export async function loadSettings(store: ACEStore): Promise<HostedSettings | null> {
  const raw = await store.read(KEY);
  if (raw === null) return null;
  return JSON.parse(new TextDecoder().decode(raw)) as HostedSettings;
}

export async function saveSettings(store: ACEStore, s: HostedSettings): Promise<void> {
  await store.write(KEY, canonicalStateBytes(s));
}

export function settingsDigest(s: HostedSettings | null): string {
  return s === null ? '' : sha256Hex(canonicalStateBytes(s));
}
