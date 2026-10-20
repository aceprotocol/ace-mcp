/**
 * The hosted-only tools: what this identity publishes in its card record and descriptor (ace_configure), its delegation credentials (ace_delegation)
 * and its ERC-8004 bindings (ace_erc8004). Each change goes through AgentContext.updateSettings as a function of the
 * settings saved at that moment (under the identity's settings lock): published first, saved only when the SDK and
 * the relay accepted it.
 */
import {
  ACE_ID_RE, MAX_DELEGATION_LIFETIME, MAX_PAY_ACCOUNTS, createDelegationCredential, isHandle, validateErc8004Binding,
  verifyErc8004Registration, type DescriptorDelegation, type JSONObject, type ProfileManifest,
} from '@ace-protocol/sdk';
import type { JSONSchema } from '@ace-protocol/sdk/tools';
import { McpToolError, closed, need, ok, type HostedTool } from './shared.js';
import { BUNDLED_PROFILES, HANDLE_SET_ONCE, type BundledProfile, type HostedSettings } from '../../agent/settings.js';
import { nowSeconds } from '../../clock.js';

const ACE_ID: JSONSchema = { type: 'string', pattern: ACE_ID_RE.source, description: 'ACE ID' };
const OBJECT: JSONSchema = { type: 'object', properties: {}, additionalProperties: true };
const WRITE = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

/** CAIP-10 account grammar (04 § Card record `pay`). */
const CAIP10 = '^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$';
const bad = (message: string) => new McpToolError('invalid_argument', message, false);

/**
 * Apply a configure call to the current settings (omitted fields are kept; `handle: ""`, `pay: []` and `ext: {}`
 * clear). A handle published at `home` is set once: changing or removing it there is refused before anything is
 * published (the relay refuses it too).
 */
function merge(s: HostedSettings, a: JSONObject, home: string): HostedSettings {
  const next: HostedSettings = { ...s };
  if (a.handle !== undefined) {
    const want = a.handle === '' ? undefined : a.handle as string;
    if (want !== undefined && !isHandle(want)) throw bad('handle must match ^[a-z][a-z0-9_-]{2,31}$');
    if (s.handle !== undefined && s.handleHome === home && want !== s.handle) {
      throw bad(`${HANDLE_SET_ONCE}; this identity's handle is @${s.handle}@${new URL(home).host}`);
    }
    if (want === undefined) { delete next.handle; delete next.handleHome; } else if (want !== s.handle) { next.handle = want; delete next.handleHome; }
  }
  if (a.contact !== undefined) next.contact = a.contact as HostedSettings['contact'];
  if (a.listed !== undefined) next.listed = a.listed as boolean;
  if (a.pay !== undefined) {
    const pay = a.pay as string[];
    if (pay.length === 0) delete next.pay;
    else if (new Set(pay).size !== pay.length) throw bad(`pay takes 1-${MAX_PAY_ACCOUNTS} distinct CAIP-10 accounts`);
    else next.pay = pay;
  }
  if (a.card !== undefined) next.card = a.card as unknown as HostedSettings['card'];
  if (a.profiles !== undefined) next.profiles = a.profiles as BundledProfile[];
  if (a.manifests !== undefined) next.manifests = a.manifests as unknown as ProfileManifest[];
  if (a.acceptProfiles !== undefined) next.acceptProfiles = a.acceptProfiles as string[];
  if (a.ext !== undefined) {
    if (Object.keys(a.ext as JSONObject).length === 0) delete next.ext; else next.ext = a.ext as Record<string, JSONObject>;
  }
  return next;
}

/**
 * Whether `next` widens who may reach the identity beyond `current`: opening contact, listing it in the directory,
 * claiming a handle, or auto-accepting another profile.
 */
function widens(current: HostedSettings, next: HostedSettings): boolean {
  return (next.contact === 'open' && current.contact !== 'open') || (next.listed && !current.listed)
    || (next.handle !== undefined && next.handle !== current.handle)
    || next.acceptProfiles.some((p) => !current.acceptProfiles.includes(p));
}

export const hostedTools: HostedTool[] = [
  {
    name: 'ace_configure',
    description: [
      'Change what your card record and descriptor publish, then republish (ace:configure). Omitted fields are kept.',
      'contact: open = strangers may send contact requests; closed (default) = only peers you admitted or invited. listed: true = in the home relay directory (default false).',
      `handle: your @name@relay-host address. ${HANDLE_SET_ONCE}.`,
      `pay: CAIP-10 accounts you ask to be paid at (1-${MAX_PAY_ACCOUNTS} distinct, e.g. eip155:8453:0x...; [] clears), claimed, not proven. card {name, description, image, tags; the "hosted" tag is always kept}, profiles ["text","commerce"], manifests (third-party profile manifests, installed and published),`,
      'acceptProfiles (auto-accept contact requests for these installed profiles), ext keyed by installed profile ID ({} clears; ace:commerce:1 is {settlement:[{method:"stablecoin",asset:CAIP-19}|{method:"stripe-link"}]}).',
      'Opening contact, listing, claiming a handle or adding acceptProfiles widens admission and also needs ace:admission. A change the relay or the card record rules refuse is not saved.',
    ].join(' '),
    scope: 'ace:configure',
    inputSchema: closed({
      contact: { type: 'string', enum: ['open', 'closed'] },
      listed: { type: 'boolean' },
      handle: { type: 'string', maxLength: 32 },
      pay: { type: 'array', items: { type: 'string', pattern: CAIP10, maxLength: 178 }, maxItems: MAX_PAY_ACCOUNTS },
      card: OBJECT,
      profiles: { type: 'array', items: { type: 'string', enum: BUNDLED_PROFILES }, maxItems: 2 },
      manifests: { type: 'array', items: OBJECT, maxItems: 16 },
      acceptProfiles: { type: 'array', items: { type: 'string', maxLength: 256 }, maxItems: 32 },
      ext: OBJECT,
    }),
    annotations: WRITE,
    async run(args, { c, has }) {
      const home = c.relay.baseUrl;
      // Merged onto, and checked against, the settings as saved when the change lands (not this call's snapshot).
      const s = await c.updateSettings((current) => {
        const next = merge(current, args, home);
        if (widens(current, next) && !has('ace:admission')) {
          throw new McpToolError('insufficient_scope', 'Opening contact, listing, claiming a handle or auto-accepting more profiles widens admission: requires ace:admission (or the owner API)', false);
        }
        return next;
      });
      return ok({
        status: 'published', ...(s.handle ? { handle: s.handle, address: `@${s.handle}@${new URL(home).host}` } : {}), card: s.card,
        ...(s.pay ? { pay: s.pay } : {}), contact: s.contact, listed: s.listed,
        profiles: (await c.network()).profiles.descriptors(), acceptProfiles: s.acceptProfiles, ...(s.ext ? { ext: s.ext } : {}),
      });
    },
  },

  {
    name: 'ace_delegation',
    description: 'A delegation credential says only "the issuer declares that the subject acts on its behalf"; it grants no execution, payment or delivery right, and the issuer revokes it by not renewing (at most 7 days). issue (ace:admission: it vouches for another identity): sign one for subject and return the descriptor entry {kel, credential} to hand to the subject. attach (ace:configure): add an entry naming you as subject to your descriptor (one per issuer, at most 4). detach (ace:configure): remove the entry of issuer. list: your attached entries.',
    actions: { list: 'ace:read', issue: 'ace:admission', attach: 'ace:configure', detach: 'ace:configure' },
    inputSchema: closed({
      action: { type: 'string', enum: ['issue', 'attach', 'detach', 'list'] },
      subject: ACE_ID, issuer: ACE_ID,
      ttlSeconds: { type: 'integer', minimum: 60, maximum: MAX_DELEGATION_LIFETIME, description: 'issue: lifetime, default 7 days' },
      entry: closed({ kel: { type: 'array' }, credential: OBJECT }, ['kel', 'credential']),
    }, ['action']),
    annotations: { ...WRITE, idempotentHint: false },
    async run(args, { c }) {
      const now = nowSeconds();
      switch (args.action) {
        case 'issue': {
          const ttl = args.ttlSeconds as number | undefined;
          const credential = await createDelegationCredential(c.identity, need(args.subject as string | undefined, 'subject'), { now, ...(ttl ? { ttl } : {}) });
          return ok({ entry: { kel: c.identity.getKel(), credential }, expiresAt: credential.expiresAt });
        }
        case 'attach': {
          const entry = need(args.entry, 'entry') as unknown as DescriptorDelegation;
          // Names us as subject; 01 § Pinning: the issuer KEL is reconciled with our pin for the issuer, when we hold one.
          const v = await (await c.network()).verifyDelegation(entry);
          if (v === null) throw new McpToolError('invalid_argument', 'the delegation credential has expired', false);
          // Entries that merely expired are dropped here (the issuer stopped renewing).
          await c.updateSettings((s) => ({
            ...s, delegations: [...s.delegations.filter((d) => d.credential.issuer !== v.issuer && d.credential.expiresAt > now), entry],
          }));
          return ok({ issuer: v.issuer, expiresAt: v.credential.expiresAt, status: 'published' });
        }
        case 'detach': {
          const issuer = need(args.issuer as string | undefined, 'issuer');
          await c.updateSettings((s) => ({ ...s, delegations: s.delegations.filter((d) => d.credential.issuer !== issuer) }));
          return ok({ issuer, status: 'published' });
        }
        default: return ok({ delegations: c.settings.delegations.map((d) => ({
          issuer: d.credential.issuer, issuedAt: d.credential.issuedAt, expiresAt: d.credential.expiresAt, live: d.credential.expiresAt > now,
        })) });
      }
    },
  },

  {
    name: 'ace_erc8004',
    description: 'Bind your descriptor to an on-chain ERC-8004 agent. The binding holds only when both directions exist: your signed descriptor names {agentRegistry (CAIP-10 registry address, e.g. eip155:8453:0x...), agentId (decimal)}, and that agent\'s registration file (tokenURI) lists the service {"name":"ACE","endpoint":"<your ACE ID>"}. attach / detach (ace:configure) edit your descriptor; list shows them; verify checks a registration document you fetched yourself against an ACE ID (this service does not read chains).',
    actions: { list: 'ace:read', verify: 'ace:read', attach: 'ace:configure', detach: 'ace:configure' },
    inputSchema: closed({
      action: { type: 'string', enum: ['attach', 'detach', 'list', 'verify'] },
      agentRegistry: { type: 'string', maxLength: 200 }, agentId: { type: 'string', maxLength: 78 },
      registration: { ...OBJECT, description: 'verify: the registration file (JSON object)' },
      aceId: { ...ACE_ID, description: 'verify: the ACE ID to look for (default: yours)' },
    }, ['action']),
    annotations: WRITE,
    async run(args, { aceId, c }) {
      switch (args.action) {
        case 'list': return ok({ erc8004: c.settings.erc8004 });
        case 'verify': return ok({ bound: verifyErc8004Registration(need(args.registration, 'registration'), (args.aceId as string | undefined) ?? aceId) });
        default: {
          const binding = validateErc8004Binding({ agentRegistry: args.agentRegistry, agentId: args.agentId });
          const { erc8004 } = await c.updateSettings((s) => {
            const others = s.erc8004.filter((b) => b.agentRegistry !== binding.agentRegistry || b.agentId !== binding.agentId);
            return { ...s, erc8004: args.action === 'attach' ? [...others, binding] : others };
          });
          return ok({ erc8004, status: 'published' });
        }
      }
    },
  },
];
