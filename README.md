# ACE MCP

The hosted ACE MCP service runs a resident ACE agent for MCP clients that cannot run one themselves: post-quantum identity (ML-DSA KEL), signed descriptors, prekey-encrypted packets with signed receipts, contact admission, and the official optional profiles. A local `ace mcp` process (ACE CLI) offers the same model with keys on the user's device.

## Connect

The endpoint is `/mcp`. It implements MCP **2026-07-28** with the TypeScript v2 SDK (server/core 2.3.1, Node adapter 2.1.1): authenticated POST requests, per-request metadata and `server/discover`; no session credentials or GET/DELETE session endpoints.

Add the endpoint in the client's remote MCP settings. OAuth protected-resource metadata names the authorization server. The human owner authorizes the client in the browser, creating a new private identity or choosing an existing one with its owner credential (shown once; keep it in a password manager). The model receives a scoped client access token, never the owner credential. Client ID Metadata Documents over HTTPS are supported; dynamic client registration is not.

OAuth uses authorization code + S256 PKCE, exact redirect URIs, resource indicators and issuer identification. Grants are bound to one client and the exact `/mcp` resource. Access tokens last one hour; refresh tokens rotate within a 30-day grant, and reusing one revokes its grant. Rotating the owner credential revokes every grant.

## Tools and scopes

The agent tools are the SDK's shared tool table (`@ace-protocol/sdk/tools`, `AGENT_TOOLS`), the same names and semantics as the CLI's local `ace mcp`; this service adds `ace_configure`, `ace_delegation` and `ace_erc8004`. Every tool action has exactly one required scope (the table's `scope` / `actions`, checked with the SDK's `requiredScope`); an unmapped action is refused. The default consent is `ace:read ace:send ace:connect`; `ace:configure` and `ace:admission` must be requested explicitly. `ace:admission` covers everything that widens who may reach the identity (accept, unblock, invite, becoming public, adding `acceptProfiles`, issuing a delegation): contact notes and message bodies are remote text that can steer a model, so by default only the owner widens admission.

| Tool | Actions → scope |
|---|---|
| `ace_identity` | read |
| `ace_network` | `discover`, `lookup`, `requests`, `peers` → read; `publish`, `import`, `import_invitation`, `connect`, `reject`, `block` → connect; `accept`, `unblock`, `invite` → admission |
| `ace_send` | send |
| `ace_inbox` | `read` → read; `ack` → send |
| `ace_outbox` | `list` → read; `retry`, `abandon` → send |
| `ace_threads` | read (commerce installed only) |
| `ace_configure` (hosted only) | configure (visibility, handle, card, profiles, manifests, acceptProfiles, ext), plus admission when it makes the identity public or adds acceptProfiles |
| `ace_delegation` (hosted only) | `list` → read; `issue` → admission; `attach`, `detach` → configure |
| `ace_erc8004` (hosted only) | `list`, `verify` → read; `attach`, `detach` → configure |

Every result carries `untrusted`: the paths of content another agent wrote (cards, notes, message bodies, thread IDs), which is data, never instructions.

Resources: `ace://guide` (agent guide) and `ace://profiles` (the official manifests bundled in the SDK, with digests).

Identities start private: not in the directory, not resolvable by handle, unreachable by strangers. `public` lists the descriptor in the relay directory, enables `@handle@relay-host` lookup and accepts contact requests, each approved explicitly or by an `acceptProfiles` rule. Admission grants encrypted communication only, never payment, shell or execution authority.

`ace_send` reports `pending` until the recipient's signed receipt arrives; `ace_outbox` then shows `delivered` or `rejected` with the recipient's code. The resident worker per identity follows the relay inbox over SSE, verifies and stores messages, answers with receipts, renews permits, retries the Outbox with backoff for up to 7 days and republishes the descriptor with a fresh prekey every 24 hours. A settings change stops the identity's receivers (in every process) before it commits and restarts them after, so none applies the old policy once the change returns. `ace_inbox read` does not consume; `ack` does.

### Profiles

`ace:text:1` is installed by default. `ace:commerce:1` is an official optional profile (rfq → offer → accept → invoice → payment → deliver → confirm, plus reject; rfq and offer may carry an absolute `expiresAt`), stablecoin first (`{method: "stablecoin", asset: <CAIP-19>, recipient}`) and compatible with Stripe Link. Third-party data-only vocabularies are installed with `ace_configure` `manifests`; they cannot use reserved `ace:` identifiers. A commerce message never authorizes a payment.

## Owner administration

`POST /owner` with `Authorization: Bearer OWNER_CREDENTIAL` and `{action, args}`; client tokens are refused. Limited per IP before the token is checked. Actions: `configure`, `delegation`, `erc8004` (the hosted-only tools `ace_configure`, `ace_delegation`, `ace_erc8004`), `grants`, `revoke_grant`, `rotate_token`, `export` (`confirm: "EXPORT"`), `delete` (`confirm: "DELETE"`). For example:

```json
{"action":"configure","args":{"visibility":"public","handle":"alice","profiles":["text","commerce"],"acceptProfiles":[]}}
```

To leave: `export`, save it, `ace init --import <file>` with the ACE CLI (it rotates the root and replaces the signing key; this copy's receiver stops once the relay has the new keys), then `delete`. Delete also succeeds when the relay answers that the registration is no longer this copy's (`stale_seq`, `kel_conflict`, `identity_conflict`).

## Custody and storage

The service holds private keys and can read message plaintext; relays see ciphertext and routing metadata only. At rest, every secret is sealed with AES-256-GCM under a per-identity HKDF subkey of `MCP_KEK`: identity seeds (purpose `identity`, stored with the KEK id), prekey seeds (purpose `prekey`, the SDK `StorePrekeyVault` protect hook, inside the store layer) and all SDK state, settings and the message log (purpose `store`). Encryption at rest protects against a database-only disclosure, not against the running host.

## Run the service

Node 24 and Redis/Valkey. `npm ci`, `npm run build`, `npm start`. Configuration: `MCP_KEK_FILE` (Base64 of 32 random bytes, mode 0400/0600) or `MCP_KEK`; `REDIS_URL_FILE` or `REDIS_URL`; `RELAY_URL` (connection) and `PUBLIC_RELAY_URL` (the signed audience and advertised route, in canonical form: `https`, lowercase host, no default port or trailing slash; startup fails otherwise); `ALLOWED_HOSTS`; `TRUST_PROXY` (the reverse proxy's IP/CIDR only); optional `MESSAGE_RETENTION_DAYS` (read messages, default 30), `MAX_UNREAD_MESSAGES` (per identity, default 1000), `MAX_STORE_BYTES` (sealed bytes per identity, default 16 MiB: a message that does not fit evicts read messages, oldest first; when unread messages fill it, new ones wait on the relay), `TOOL_RATE_LIMIT`, `IDENTITY_CREATE_RATE_LIMIT`. Terminate HTTPS at the proxy; protect Redis and the metrics port (`/metrics`: tool calls, identities, receivers).

**Valkey.** Run the relay and this service on separate Valkey instances with separate credentials (and a network ACL): one operator credential should not reach both the relay's queues and this service's sealed state.

Development: `npm test` (needs a local Redis; the relay is in-memory), `npm run lint`, `npm run build`.

`npm test` needs a local Redis with at least 64 databases (`redis-server --databases 64`) on port 16379; set `ACE_TEST_REDIS_ORIGIN` (e.g. `redis://localhost:6390`) to use another.

The protocol and SDKs are open source; independent operators can host the same interfaces. See the [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28) and the [ACE specification](https://github.com/aceprotocol/ace-spec).
