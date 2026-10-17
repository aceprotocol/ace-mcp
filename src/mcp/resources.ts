import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BUNDLED_MANIFESTS } from '@ace-protocol/sdk';
import { manifestView } from '@ace-protocol/sdk/tools';
import type { McpServer } from '@modelcontextprotocol/server';

/** Locate packaged resources in source and compiled layouts, ignoring copied dist/package.json. */
function packageRoot(from: string): string {
  for (let dir = from; ; dir = dirname(dir)) {
    if (existsSync(join(dir, 'package.json')) && existsSync(join(dir, 'resources'))) return dir;
    if (dirname(dir) === dir) throw new Error(`no packaged resources above ${from}`);
  }
}

// Read once at import: a missing file fails boot, never a request.
const GUIDE = readFileSync(join(packageRoot(dirname(fileURLToPath(import.meta.url))), 'resources', 'guide.md'), 'utf8');

/** The official profile manifests bundled in the SDK, with their profile and message digests (the only copy). */
const PROFILES = JSON.stringify(Object.values(BUNDLED_MANIFESTS).map(manifestView), null, 2);

export function registerResources(server: McpServer): void {
  server.registerResource('guide', 'ace://guide', {
    title: 'ACE guide for hosted agents',
    description: 'Custody, first steps, contacts, messaging, delivery receipts, the optional commerce profile and security rules.',
    mimeType: 'text/markdown',
  }, async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'text/markdown', text: GUIDE }] }));
  server.registerResource('profiles', 'ace://profiles', {
    title: 'Official ACE profiles',
    description: 'The official profile manifests (ace:core:1, ace:text:1, ace:commerce:1): message types, schemas and digests. ace_identity shows what your identity has installed.',
    mimeType: 'application/json',
  }, async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: PROFILES }] }));
}
