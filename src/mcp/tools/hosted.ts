/**
 * The hosted-only tools: what this identity publishes in its card record and descriptor (ace_configure), its
 * `ace:delegation:1` credentials (ace_delegation; published in the descriptor's `ext`) and its ERC-8004 bindings
 * (ace_erc8004; card record members). Each change goes through AgentContext.updateSettings as a function of the
 * settings saved at that moment (under the identity's settings lock): published first, saved only when the SDK and
 * the relay accepted it.
 */
import {
  ACEError, ACE_ID_RE, CAIP10_RE, HANDLE_RE, MAX_CARD_ERC8004, MAX_DELEGATION_CREDENTIALS, MAX_DELEGATION_CREDENTIAL_LIFETIME, MAX_PAY_ACCOUNTS,
  createDelegationCredential, handleAddress, validateErc8004Binding, verifyErc8004Registration, type JSONObject, type ProfileManifest,
} from '@ace-protocol/sdk';
import type { JSONSchema } from '@ace-protocol/sdk/tools';
import { McpToolError, closed, need, ok, type HostedTool } from './shared.js';
import { BUNDLED_PROFILES, type BundledProfile, type HostedSettings } from '../../agent/settings.js';
import { nowSeconds } from '../../clock.js';

const ACE_ID: JSONSchema = { type: 'string', pattern: ACE_ID_RE.source, description: 'ACE ID' };
const OBJECT: JSONSchema = { type: 'object', properties: {}, additionalProperties: true };
const WRITE = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

/** One line on the set-once handle rule (tool description and refusals). */
const HANDLE_SET_ONCE = 'a handle is permanent: set once per home relay, it can never be changed or removed there';

/**
 * Apply a configure call to the current settings (omitted fields are kept; `handle: ""`, `pay: []` and `ext: {}`
 * clear). The set-once handle rule is the relay's: a change it refuses comes back through `explainRefusal`.
 */
function merge(s: HostedSettings, a: JSONObject): HostedSettings {
  const next: HostedSettings = { ...s };
  if (a.handle === '') delete next.handle; else if (a.handle !== undefined) next.handle = a.handle as string;
  if (a.contact !== undefined) next.contact = a.contact as HostedSettings['contact'];
  if (a.listed !== undefined) next.listed = a.listed as boolean;
  if (a.pay !== undefined) {
    if ((a.pay as string[]).length === 0) delete next.pay; else next.pay = a.pay as string[];
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
 * A publish the relay refused, explained (the relay's code becomes the error code): a handle another identity holds
 * (`handle_taken`), or a card record without the handle this identity already holds at that relay (`invalid_argument`,
 * explained only when `next` carries a handle or `previous` had one; otherwise the relay's answer stands as is).
 */
function explainRefusal(err: unknown, next: HostedSettings, previous: HostedSettings, home: string): unknown {
  if (!(err instanceof ACEError) || err.code !== 'relay_rejected') return err;
  const opts = { cause: err, ...(err.status !== undefined ? { status: err.status } : {}), relayCode: err.relayCode };
  if (err.relayCode === 'handle_taken' && next.handle) {
    return new ACEError('handle_taken', `${handleAddress(next.handle, home)} belongs to another identity; choose another handle`, opts);
  }
  if (err.relayCode === 'invalid_argument' && (next.handle !== undefined || previous.handle !== undefined)) {
    return new ACEError('invalid_argument', `${home} refused the card record (${err.detail}): ${HANDLE_SET_ONCE}. `
      + 'If this identity already holds a handle there, configure exactly that one', opts);
  }
  return err;
}

/** Whether two `pay` lists name different account sets (order-insensitive; absent is empty). */
function payChanged(a: string[] | undefined, b: string[] | undefined): boolean {
  const x = new Set(a ?? []), y = new Set(b ?? []);
  return x.size !== y.size || [...x].some((p) => !y.has(p));
}

/**
 * Whether `next` needs ace:admission beyond `current`: it widens who may reach the identity (opening contact, listing
 * it in the directory, claiming a handle, auto-accepting another profile), or it changes where the agent asks to be
 * paid (any change of the `pay` set: redirecting or clearing payee accounts is as sensitive).
 */
function needsAdmission(current: HostedSettings, next: HostedSettings): boolean {
  return (next.contact === 'open' && current.contact !== 'open') || (next.listed && !current.listed)
    || (next.handle !== undefined && next.handle !== current.handle)
    || next.acceptProfiles.some((p) => !current.acceptProfiles.includes(p))
    || payChanged(current.pay, next.pay);
}

export const hostedTools: HostedTool[] = [
  {
    name: 'ace_configure',
    description: [
      'Change what your card record and descriptor publish, then republish (ace:configure). Omitted fields are kept.',
      'contact: open = strangers may send contact requests; closed (default) = only peers you admitted or invited. listed: true = in the home relay directory (default false).',
      `handle: your @name@relay-host address (3-32 of a-z, 0-9 and single inner hyphens, starting with a letter). ${HANDLE_SET_ONCE}.`,
      `pay: CAIP-10 accounts you ask to be paid at (1-${MAX_PAY_ACCOUNTS} distinct, e.g. eip155:8453:0x...; [] clears), claimed, not proven. card {description, image, tags; no name: your handle names you; the "hosted" tag is always kept}, profiles ["text","commerce"], manifests (third-party profile manifests, installed and published),`,
      'acceptProfiles (auto-accept contact requests for these installed profiles), ext keyed by installed profile ID ({} clears; ace:commerce:1 is {settlement:[{method:"stablecoin",asset:CAIP-19}|{method:"stripe-link"}]}).',
      'Opening contact, listing, claiming a handle or adding acceptProfiles widens admission, and any change of pay redirects payments: these also need ace:admission. A change the relay or the card record rules refuse is not saved.',
    ].join(' '),
    scope: 'ace:configure',
    inputSchema: closed({
      contact: { type: 'string', enum: ['open', 'closed'] },
      listed: { type: 'boolean' },
      handle: { type: 'string', maxLength: 32, pattern: `^$|${HANDLE_RE.source}` },
      pay: { type: 'array', items: { type: 'string', pattern: CAIP10_RE.source, maxLength: 178 }, maxItems: MAX_PAY_ACCOUNTS, uniqueItems: true },
      card: OBJECT,
      profiles: { type: 'array', items: { type: 'string', enum: BUNDLED_PROFILES }, maxItems: 2 },
      manifests: { type: 'array', items: OBJECT, maxItems: 16 },
      acceptProfiles: { type: 'array', items: { type: 'string', maxLength: 256 }, maxItems: 32 },
      ext: OBJECT,
    }),
    annotations: WRITE,
    async run(args, { c, has }) {
      const home = c.relay.baseUrl;
      let change: { current: HostedSettings; next: HostedSettings } | undefined;
      // Merged onto, and checked against, the settings as saved when the change lands (not this call's snapshot).
      const s = await c.updateSettings((current) => {
        const next = merge(current, args);
        if (needsAdmission(current, next) && !has('ace:admission')) {
          throw new McpToolError('insufficient_scope', 'Opening contact, listing, claiming a handle, auto-accepting more profiles or changing pay accounts requires ace:admission (or the owner API)', false);
        }
        change = { current, next };
        return next;
      }).catch((e: unknown) => { throw change ? explainRefusal(e, change.next, change.current, home) : e; });
      return ok({
        status: 'published', ...(s.handle ? { handle: s.handle, address: handleAddress(s.handle, home) } : {}), card: s.card,
        ...(s.pay ? { pay: s.pay } : {}), contact: s.contact, listed: s.listed,
        profiles: (await c.network()).profiles.descriptors(), acceptProfiles: s.acceptProfiles, ...(s.ext ? { ext: s.ext } : {}),
      });
    },
  },

  {
    name: 'ace_delegation',
    description: `An ace:delegation:1 credential says only "the issuer declares that the subject acts on its behalf"; it grants no execution, payment or delivery right, and the issuer revokes it by not renewing (at most 7 days). issue (ace:admission: it vouches for another identity): sign one for subject and return the credential to hand to the subject. attach (ace:configure): verify a credential naming you as subject under a fresh lookup of its issuer, then publish it in your descriptor's ext["ace:delegation:1"] (one per issuer, at most ${MAX_DELEGATION_CREDENTIALS}). detach (ace:configure): remove the credential of issuer. list: your attached credentials.`,
    actions: { list: 'ace:read', issue: 'ace:admission', attach: 'ace:configure', detach: 'ace:configure' },
    inputSchema: closed({
      action: { type: 'string', enum: ['issue', 'attach', 'detach', 'list'] },
      subject: ACE_ID, issuer: ACE_ID,
      ttlSeconds: { type: 'integer', minimum: 60, maximum: MAX_DELEGATION_CREDENTIAL_LIFETIME, description: 'issue: lifetime, default 7 days' },
      credential: { ...OBJECT, description: 'attach: the credential {issuer, subject, issuedAt, expiresAt, signature}' },
    }, ['action']),
    annotations: { ...WRITE, idempotentHint: false },
    async run(args, { aceId, c }) {
      const now = nowSeconds();
      switch (args.action) {
        case 'issue': {
          const ttl = args.ttlSeconds as number | undefined;
          const credential = await createDelegationCredential(c.identity, need(args.subject as string | undefined, 'subject'), { now, ...(ttl ? { ttl } : {}) });
          return ok({ credential, expiresAt: credential.expiresAt });
        }
        case 'attach': {
          const value = need(args.credential, 'credential');
          if ((value as JSONObject).subject !== aceId) throw new ACEError('invalid_authorization', 'the credential names another subject');
          // profiles/delegation.md § Verifying a credential: the issuer is looked up and pinned; a lookup failure is reported as itself.
          const v = await (await c.network()).verifyDelegation(value);
          // Credentials that merely expired are dropped here (the issuer stopped renewing).
          await c.updateSettings((s) => {
            const kept = s.delegations.filter((d) => d.issuer !== v.issuer && d.expiresAt > now);
            if (kept.length >= MAX_DELEGATION_CREDENTIALS) {
              throw new McpToolError('invalid_argument', `a descriptor carries at most ${MAX_DELEGATION_CREDENTIALS} delegation credentials; detach one first`, false);
            }
            return { ...s, delegations: [...kept, v] };
          });
          return ok({ issuer: v.issuer, expiresAt: v.expiresAt, status: 'published' });
        }
        case 'detach': {
          const issuer = need(args.issuer as string | undefined, 'issuer');
          await c.updateSettings((s) => ({ ...s, delegations: s.delegations.filter((d) => d.issuer !== issuer) }));
          return ok({ issuer, status: 'published' });
        }
        default: return ok({ delegations: c.settings.delegations.map((d) => ({
          issuer: d.issuer, issuedAt: d.issuedAt, expiresAt: d.expiresAt, live: d.expiresAt > now,
        })) });
      }
    },
  },

  {
    name: 'ace_erc8004',
    description: `Bind your card record to an on-chain ERC-8004 agent. The binding holds only when both directions exist: your signed card record names {agentRegistry (CAIP-10 registry address, e.g. eip155:8453:0x...), agentId (decimal for eip155)}, and that agent's registration file (tokenURI) lists the service {"name":"ACE","endpoint":"<your ACE ID>"}. attach / detach (ace:configure) edit your card record (at most ${MAX_CARD_ERC8004} bindings); list shows them; verify checks a registration document you fetched yourself against an ACE ID (this service does not read chains).`,
    actions: { list: 'ace:read', verify: 'ace:read', attach: 'ace:configure', detach: 'ace:configure' },
    inputSchema: closed({
      action: { type: 'string', enum: ['attach', 'detach', 'list', 'verify'] },
      agentRegistry: { type: 'string', maxLength: 200 }, agentId: { type: 'string', maxLength: 128 },
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
            if (args.action === 'attach' && others.length >= MAX_CARD_ERC8004) {
              throw new McpToolError('invalid_argument', `a card record carries at most ${MAX_CARD_ERC8004} ERC-8004 bindings; detach one first`, false);
            }
            return { ...s, erc8004: args.action === 'attach' ? [...others, binding] : others };
          });
          return ok({ erc8004, status: 'published' });
        }
      }
    },
  },
];
