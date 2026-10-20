import {
  ACEError, canonicalStateBytes, sha256Hex, validateCard,
  type ACEErrorCode, type ACEStore, type AgentCard, type Contact, type DescriptorDelegation, type Erc8004Binding, type JSONObject, type ProfileManifest,
} from '@ace-protocol/sdk';

/** The reserved card tag: this service holds the identity's keys. */
export const HOSTED_TAG = 'hosted';
export const BUNDLED_PROFILES = ['text', 'commerce'] as const;
export type BundledProfile = (typeof BUNDLED_PROFILES)[number];

/**
 * One hosted identity's local policy and published claims. Only the owner (or a client holding `ace:configure`)
 * changes it; a remote message never does. Saved sealed in the identity's store, and only after the SDK published the
 * descriptor and card record built from it (the SDK's rules and the relay are the one validation).
 */
export interface HostedSettings {
  /** Card record: the handle at the home relay. Set once: after it was published there it can never change. */
  handle?: string;
  /** The home relay `handle` was published at (recorded after a successful publish); the handle is fixed there. */
  handleHome?: string;
  /** Card record: the presentation card (always carries the `hosted` tag). */
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
  return { contact: 'closed', listed: false, card: hostedCard({ name }), profiles: ['text'], manifests: [], acceptProfiles: [], delegations: [], erc8004: [] };
}

/**
 * The saved settings. Settings saved before card records carry `visibility`: `public` reads as `contact: open` +
 * `listed: true`, `private` (or none) as `contact: closed` + `listed: false`; the next save drops it.
 */
export async function loadSettings(store: ACEStore): Promise<HostedSettings | null> {
  const raw = await store.read(KEY);
  if (raw === null) return null;
  const { visibility, ...rest } = JSON.parse(new TextDecoder().decode(raw)) as Partial<HostedSettings> & { visibility?: unknown };
  const legacy = visibility === 'public' ? { contact: 'open', listed: true } as const : { contact: 'closed', listed: false } as const;
  return { ...legacy, ...rest } as HostedSettings;
}

export async function saveSettings(store: ACEStore, s: HostedSettings): Promise<void> {
  await store.write(KEY, canonicalStateBytes(s));
}

/** One line on the set-once handle rule (tool descriptions and refusals). */
export const HANDLE_SET_ONCE = 'a handle is permanent: set once per home relay, it can never be changed or removed there';

/** `s` after a successful publish at `home`: a handle published there is fixed there. */
export function publishedAt(s: HostedSettings, home: string): HostedSettings {
  const next = { ...s };
  if (next.handle) next.handleHome = home; else delete next.handleHome;
  return next;
}

/**
 * A publish the relay refused, explained (the relay's code becomes the error code): a handle another identity holds
 * (`handle_taken`), or a card record without the handle this identity already holds at that relay (`invalid_argument`,
 * explained only when `s` carries a handle or `previous` had one; otherwise the relay's answer stands as is).
 */
export function explainRefusal(err: unknown, s: HostedSettings, home: string, previous?: HostedSettings | null): unknown {
  if (!(err instanceof ACEError) || err.code !== 'relay_rejected') return err;
  const host = new URL(home).host;
  const opts = { cause: err, ...(err.status !== undefined ? { status: err.status } : {}), relayCode: err.relayCode };
  if (err.relayCode === 'handle_taken' && s.handle) {
    return new ACEError('handle_taken' as ACEErrorCode, `@${s.handle}@${host} belongs to another identity; choose another handle`, opts);
  }
  if (err.relayCode === 'invalid_argument' && (s.handle !== undefined || previous?.handle !== undefined)) {
    return new ACEError('invalid_argument', `${home} refused the card record (${err.detail}): ${HANDLE_SET_ONCE}. `
      + 'If this identity already holds a handle there, configure exactly that one', opts);
  }
  return err;
}

export function settingsDigest(s: HostedSettings | null): string {
  return s === null ? '' : sha256Hex(canonicalStateBytes(s));
}
