import type { SoftwareIdentity } from '@ace-protocol/sdk';
import type { ToolDeps } from '../mcp/tools/shared.js';
import { rateBucket } from '../store/keyspace.js';
import type { IdentityRecord } from './vault.js';
import { defaultSettings } from '../agent/settings.js';

export type ProvisionDeps = Pick<ToolDeps, 'vault' | 'runtime' | 'rateLimiter' | 'config' | 'logger'>;

/**
 * The one identity-creation flow (owner-approved OAuth `action=create`): per-IP creation limit
 * (IDENTITY_CREATE_RATE_LIMIT per hour), vault.create, private default settings and the first descriptor (whose
 * publish registers the identity at the relay, on behalf of `ip`); the vault record is deleted if any step fails (the
 * token was never shown).
 */
export async function provisionIdentity(
  deps: ProvisionDeps,
  input: { name: string },
  ip: string,
): Promise<{ identity: SoftwareIdentity; token: string; record: IdentityRecord }> {
  const settings = defaultSettings(input.name); // validates the name before anything is created
  await deps.rateLimiter.enforce(rateBucket.create(ip), deps.config.identityCreateRateLimit, 3600);
  const created = await deps.vault.create();
  const aceId = created.identity.getACEId();
  try {
    await deps.runtime.withIdentity(aceId, ip, (c) => c.updateSettings(() => settings));
  } catch (e) {
    await rollbackProvisioned(deps, aceId, ip);
    throw e;
  }
  return created;
}

/**
 * Undo a provisionIdentity whose token was never handed out (e.g. the OAuth code could not be stored): best-effort
 * relay unregister, then delete the vault record. Never throws.
 */
export async function rollbackProvisioned(deps: ProvisionDeps, aceId: string, ip: string): Promise<void> {
  try {
    await deps.runtime.withIdentity(aceId, ip, (c) => c.unregister());
  } catch (err) {
    deps.logger.error({ err, aceId }, 'rollback: relay unregister failed');
  }
  await deps.vault.delete(aceId).catch((err: unknown) => deps.logger.error({ err, aceId }, 'rollback: identity delete failed'));
}
