// An in-memory relay implementing the minimal relay binding behind `fetch` (after sdk-ts tests/helpers.ts), plus
// `GET /v1/listen` SSE and `POST /v1/unregister`, for the receiver workers. Packet signatures are not checked: the
// receiving Inbox does that.
import {
  ACEError, compareStreamIds, decodePacket, parseAuthHeaders, verifyAuthHeaders, verifyPermit, verifyPublishedAgent,
  verifyRegistrationRequest, type KelState, type PublishedAgent, type RelayAuthRequest,
} from '@ace-protocol/sdk';

export const RELAY = 'https://relay.test';

class HTTPError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}

interface Entry { streamId: string; packet: unknown; raw: string }
type Listener = (e: Entry) => void;

export class FakeRelay {
  readonly baseUrl: string;
  clock: () => number;
  kels = new Map<string, KelState>();
  descriptors = new Map<string, PublishedAgent>();
  blocks = new Map<string, { blocked: boolean; revision: number }>();
  queues = new Map<string, Entry[]>();
  listeners = new Map<string, Set<Listener>>();
  /** Open listen streams per identity: a registration that changes the KEL ends them (they were authenticated by the old key). */
  readonly #streams = new Map<string, Set<ReadableStreamDefaultController<Uint8Array>>>();
  nonces = new Set<string>();
  seq = 0;
  sent: Array<{ packet: unknown; permit?: unknown }> = [];
  requests: Array<{ method: string; path: string; forwardedFor: string | null }> = [];

  constructor(clock: () => number = () => Math.floor(Date.now() / 1000), baseUrl = RELAY) { this.clock = clock; this.baseUrl = baseUrl; }

  fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    const method = init?.method ?? 'GET';
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => { headers[k] = v; });
    this.requests.push({ method, path: url.pathname, forwardedFor: headers['x-forwarded-for'] ?? null });
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    try {
      if (method === 'GET' && url.pathname === '/v1/listen') return this.#listen(url, headers, init?.signal ?? undefined);
      const out = await this.route(method, url, headers, body);
      return new Response(JSON.stringify(out), { status: 200, headers: { 'content-type': 'application/json' } });
    } catch (e) {
      if (e instanceof HTTPError) return new Response(JSON.stringify({ error: e.code }), { status: e.status, headers: { 'content-type': 'application/json' } });
      if (e instanceof ACEError) return new Response(JSON.stringify({ error: e.code }), { status: 400, headers: { 'content-type': 'application/json' } });
      throw e;
    }
  };

  #auth(headers: Record<string, string>, req: RelayAuthRequest): string {
    const auth = parseAuthHeaders(headers);
    const state = this.kels.get(auth.aceId);
    if (!state) throw new HTTPError(403, 'not_registered');
    verifyAuthHeaders(auth, req, state, { audience: this.baseUrl, clock: this.clock });
    if (this.nonces.has(auth.nonce)) throw new HTTPError(409, 'replay');
    this.nonces.add(auth.nonce);
    return auth.aceId;
  }

  #public(id: string): PublishedAgent | undefined {
    const d = this.descriptors.get(id);
    return d && d.descriptor.visibility === 'public' && d.descriptor.expiresAt > this.clock() ? d : undefined;
  }

  #listen(url: URL, headers: Record<string, string>, signal?: AbortSignal): Response {
    const since = url.searchParams.get('since') ?? '-';
    let owner: string;
    try {
      owner = this.#auth(headers, { action: 'listen', since });
    } catch (e) {
      const err = e instanceof HTTPError ? e : new HTTPError(401, e instanceof ACEError ? e.code : 'invalid_auth');
      return new Response(JSON.stringify({ error: err.code }), { status: err.status, headers: { 'content-type': 'application/json' } });
    }
    const enc = new TextEncoder();
    const frame = (event: string, e: Entry) => enc.encode(`event: ${event}\nid: ${e.streamId}\ndata: ${JSON.stringify({ packet: e.packet })}\n\n`);
    let listener: Listener | undefined;
    const stream = new ReadableStream<Uint8Array>({
      start: (controller) => {
        controller.enqueue(enc.encode('event: connected\ndata: {}\n\n'));
        for (const e of this.queues.get(owner) ?? []) if (since === '-' || compareStreamIds(e.streamId, since) > 0) controller.enqueue(frame('catchup', e));
        listener = (e) => { try { controller.enqueue(frame('message', e)); } catch { /* closed */ } };
        const set = this.listeners.get(owner) ?? new Set();
        set.add(listener);
        this.listeners.set(owner, set);
        const streams = this.#streams.get(owner) ?? new Set();
        streams.add(controller);
        this.#streams.set(owner, streams);
        signal?.addEventListener('abort', () => {
          this.listeners.get(owner)?.delete(listener!);
          try { controller.close(); } catch { /* closed */ }
        }, { once: true });
      },
      cancel: () => { this.listeners.get(owner)?.delete(listener!); },
    });
    return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } });
  }

  async route(method: string, url: URL, headers: Record<string, string>, body: any): Promise<unknown> {
    const path = url.pathname;
    const now = this.clock();
    if (method === 'POST' && path === '/v1/register') {
      const { state } = verifyRegistrationRequest(body, { audience: this.baseUrl, clock: this.clock });
      const old = this.kels.get(state.aceId);
      if (old && state.seq < old.seq) throw new HTTPError(401, 'stale_seq'); // a strict prefix of the registered KEL
      this.kels.set(state.aceId, state);
      if (old && old.lastHash !== state.lastHash) {
        for (const c of this.#streams.get(state.aceId) ?? []) try { c.close(); } catch { /* closed */ }
        this.#streams.delete(state.aceId);
      }
      return { ok: true, status: 'registered' };
    }
    if (method === 'POST' && path === '/v1/unregister') {
      const owner = this.#auth(headers, { action: 'unregister' });
      this.kels.delete(owner);
      this.descriptors.delete(owner);
      this.queues.delete(owner);
      return { ok: true };
    }
    if (method === 'POST' && path === '/v1/descriptor') {
      const { agent, state } = verifyPublishedAgent(body, now);
      const reg = this.kels.get(state.aceId);
      if (!reg || reg.lastHash !== state.lastHash) throw new HTTPError(403, 'not_registered');
      if (!agent.descriptor.relays.includes(this.baseUrl)) throw new HTTPError(400, 'invalid_argument');
      this.descriptors.set(state.aceId, agent);
      return { ok: true };
    }
    let m = /^\/v1\/descriptor\/(.+)$/.exec(path);
    if (method === 'GET' && m && m[1] !== 'resolve') {
      const d = this.#public(decodeURIComponent(m[1]));
      if (!d) throw new HTTPError(404, 'unknown_peer');
      return d;
    }
    if (method === 'POST' && path === '/v1/descriptor/resolve') {
      const d = this.descriptors.get(body.aceId), reg = this.kels.get(body.aceId);
      try {
        if (!d || !reg) throw new Error();
        const p = verifyPermit(body.permit, reg, undefined, now);
        if (this.blocks.get(`${body.aceId}|${p.subject}`)?.blocked) throw new Error();
      } catch { throw new HTTPError(404, 'unknown_peer'); }
      return d;
    }
    m = /^\/v1\/handles\/(.+)$/.exec(path);
    if (method === 'GET' && m) {
      const d = [...this.descriptors.values()].find((a) => a.descriptor.handle === m![1] && this.#public(a.descriptor.aceId));
      if (!d) throw new HTTPError(404, 'unknown_peer');
      return d;
    }
    if (method === 'GET' && path === '/v1/descriptors') {
      const profile = url.searchParams.get('profile');
      const agents = [...this.descriptors.values()].filter((a) => this.#public(a.descriptor.aceId) && (!profile || a.descriptor.profiles.some((p) => p.id === profile)));
      return { agents, cursor: null };
    }
    if (method === 'POST' && path === '/v1/blocks') {
      const owner = this.#auth(headers, { action: 'block', peer: body.peer, blocked: body.blocked, revision: body.revision });
      const k = `${owner}|${body.peer}`, old = this.blocks.get(k);
      if (old && body.revision <= old.revision) throw new HTTPError(409, 'stale_revision');
      this.blocks.set(k, { blocked: body.blocked, revision: body.revision });
      return { ok: true };
    }
    if (method === 'POST' && path === '/v1/send') {
      const packet = decodePacket(body.packet);
      if (packet.timestamp > now + 300 || packet.timestamp < now - 604800) throw new HTTPError(400, 'stale_timestamp');
      const reg = this.kels.get(packet.to);
      if (!reg) throw new HTTPError(404, 'unknown_peer');
      const raw = JSON.stringify(body.packet);
      const q = this.queues.get(packet.to) ?? [];
      if (q.some((e) => e.raw === raw)) return { ok: true };
      if (this.blocks.get(`${packet.to}|${packet.from}`)?.blocked) throw new HTTPError(403, 'not_permitted');
      if (body.permit) {
        try { verifyPermit(body.permit, reg, packet.from, now); if (body.permit.issuer !== packet.to) throw new Error(); }
        catch { throw new HTTPError(403, 'not_permitted'); }
      } else if (!this.#public(packet.to)) {
        throw new HTTPError(403, 'not_permitted');
      }
      this.sent.push(body);
      const entry = { streamId: `${Date.now()}-${this.seq++}`, packet: body.packet, raw };
      q.push(entry);
      this.queues.set(packet.to, q);
      for (const l of this.listeners.get(packet.to) ?? []) l(entry);
      return { ok: true };
    }
    if (method === 'GET' && path === '/v1/inbox') {
      const since = url.searchParams.get('since') ?? '-', limit = Number(url.searchParams.get('limit') ?? 100);
      const owner = this.#auth(headers, { action: 'inbox', since, limit });
      const q = (this.queues.get(owner) ?? []).filter((e) => since === '-' || compareStreamIds(e.streamId, since) > 0).slice(0, limit);
      return { messages: q.map((e) => ({ streamId: e.streamId, packet: e.packet })), cursor: q.length ? q[q.length - 1].streamId : null };
    }
    if (method === 'POST' && path === '/v1/inbox/ack') {
      const through = url.searchParams.get('through')!;
      const owner = this.#auth(headers, { action: 'inbox-ack', through });
      this.queues.set(owner, (this.queues.get(owner) ?? []).filter((e) => compareStreamIds(e.streamId, through) > 0));
      return { ok: true };
    }
    throw new HTTPError(404, 'not_found');
  }

  pending(aceId: string): number { return this.queues.get(aceId)?.length ?? 0; }
}
