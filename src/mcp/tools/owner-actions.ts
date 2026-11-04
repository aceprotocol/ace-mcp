import { ACEError } from '@ace-protocol/sdk';
import { McpToolError, closed, ok, type HostedTool } from './shared.js';

/**
 * The custody hand-over. The CLI import re-keys (rotates the root, replaces the signing key) and registers the new key
 * event log, which supersedes this copy: its receiver stops, and delete still succeeds afterwards.
 */
export const IMPORT_INSTRUCTIONS = 'Save this JSON to a file and run `ace init --import <file>` with the ACE CLI: it rotates the root and replaces the signing key, so this service holds nothing current afterwards (its receiver stops once the relay has the new keys). Then call the owner delete action with confirm DELETE to erase the copy held here.';

/**
 * Unregister answers that mean the relay's registration is no longer this copy's: none (`not_registered`), a newer
 * key event log (`stale_seq`: imported and re-keyed elsewhere), a fork (`kel_conflict`) or a newer registration
 * (`identity_conflict`). Deleting the copy held here is then still right.
 */
const NOT_OURS = new Set(['stale_seq', 'kel_conflict', 'identity_conflict']);
const registrationGone = (e: unknown) => e instanceof ACEError && (e.code === 'not_registered' || (e.relayCode !== undefined && NOT_OURS.has(e.relayCode)));

const confirm = (word: string) => closed({ confirm: { type: 'string', maxLength: 16, description: `Must be the literal string ${word}` } }, ['confirm']);

/** Owner API actions (POST /owner); never registered as MCP tools and never reachable with a client token. */
export const ownerActions: HostedTool[] = [
  {
    name: 'rotate_token', ownerOnly: true,
    description: 'Issue a new owner token and invalidate the current one and every client grant derived from it.',
    inputSchema: closed({}),
    async run(_args, { deps, aceId }) {
      const token = await deps.vault.rotateToken(aceId);
      return ok({ aceId, token }, `New token (shown once): ${token}\nThe previous token no longer works.`);
    },
  },

  {
    name: 'export', ownerOnly: true,
    description: 'Return the identity export (root, next-root and signing seeds and the KEL) so you can run it yourself.',
    inputSchema: confirm('EXPORT'),
    async run(args, { deps, aceId, c }) {
      if (args.confirm !== 'EXPORT') throw new McpToolError('confirmation_required', 'Pass confirm: "EXPORT" to export private keys.', false);
      const exp = c.identity.exportPrivateKey();
      await deps.vault.markExported(aceId);
      return ok({ aceId, ...exp, importInstructions: IMPORT_INSTRUCTIONS }, `Private keys for ${aceId} (never share):\n${JSON.stringify(exp)}\n${IMPORT_INSTRUCTIONS}`);
    },
  },

  {
    name: 'delete', ownerOnly: true,
    description: 'Stop the receiver, unregister from the relay and erase keys, settings, contacts and messages held here. Irreversible unless you exported first.',
    inputSchema: confirm('DELETE'),
    async run(args, { deps, aceId, c }) {
      if (args.confirm !== 'DELETE') throw new McpToolError('confirmation_required', 'Pass confirm: "DELETE" to delete the identity.', false);
      // The durable marker first: from here on every process treats the identity as gone (auth, worker scans, upkeep)
      // and its store refuses writes, so no client can persist the registration timestamp the SDK writes before each
      // register: nothing registers it again, including the SDK's register-on-publish.
      await deps.vault.beginDelete(aceId);
      try {
        // Stop this process's receiver and let its other in-flight calls on the identity finish (bounded), so none
        // publishes or writes afterwards. Another replica's in-flight calls are not drained; they can neither write nor
        // register. The residual window: a register on another replica whose timestamp was persisted before the marker
        // and whose request reaches the relay after this unregister. This unregister's timestamp is above it (it reads
        // the same persisted ordering under the same store lock), so the relay refuses that register for as long as it
        // keeps the unregister barrier (at least OFFLINE_WINDOW_SECONDS, 02 / 07).
        await deps.runtime.drain(aceId, c);
        await c.unregister();
      } catch (e) {
        if (!registrationGone(e)) {
          await deps.vault.cancelDelete(aceId).catch((err: unknown) => deps.logger.error({ err, aceId }, 'delete: could not clear the deletion marker'));
          throw e;
        }
      }
      await deps.vault.delete(aceId);
      return ok({ ok: true, aceId }, `Deleted ${aceId}.`);
    },
  },
];
