// The package.json / package-lock.json halves of vendor-local-deps.sh (see there).
//   node vendor-lock.mjs rewrite <sdk-lock> <tarball>   # in the target directory
//   node vendor-lock.mjs verify  <sdk-lock> <app-lock>
import { readFileSync, writeFileSync } from 'node:fs';

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const nameOf = (k) => k.slice(k.lastIndexOf('node_modules/') + 'node_modules/'.length);

/** Every non-dev, non-link `node_modules/…` entry of a lock (any nesting depth), by package name. */
function runtimeDeps(lockPath) {
  const deps = new Map();
  for (const [k, v] of Object.entries(readJson(lockPath).packages)) {
    if (!k.includes('node_modules/') || v.dev || v.link) continue;
    const name = nameOf(k);
    const seen = deps.get(name);
    if (seen && seen.version !== v.version) throw new Error(`sdk-ts lock holds two versions of ${name} (${seen.version}, ${v.version}); cannot pin with one override`);
    deps.set(name, v);
  }
  if (deps.size === 0) throw new Error('no runtime dependencies in the sdk-ts lock');
  return deps;
}

const [mode, sdkLock, arg] = process.argv.slice(2);
const sdk = runtimeDeps(sdkLock);

if (mode === 'rewrite') {
  const pkg = readJson('package.json');
  if (!pkg.dependencies?.['@ace-protocol/sdk']) throw new Error('@ace-protocol/sdk is not a dependency');
  pkg.dependencies['@ace-protocol/sdk'] = `file:vendor/${arg}`;
  for (const name of sdk.keys()) {
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      if (pkg[field]?.[name] !== undefined) throw new Error(`${name} is also a direct ${field} entry; an override would conflict with it`);
    }
  }
  const pins = Object.fromEntries([...sdk].map(([name, v]) => [name, v.version]));
  pkg.overrides = { ...(pkg.overrides ?? {}), ...pins };
  writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
  console.log('vendor-local-deps: overrides ' + Object.entries(pins).map(([n, v]) => `${n}@${v}`).join(', '));
} else if (mode === 'verify') {
  // Backstop: every lock entry of the pinned packages must equal sdk-ts's locked one.
  const app = Object.entries(readJson(arg).packages).filter(([k]) => k.includes('node_modules/'));
  const bad = [];
  let seen = 0;
  for (const [k, v] of app) {
    const want = sdk.get(nameOf(k));
    if (!want) continue;
    seen++;
    if (want.version !== v.version || want.integrity !== v.integrity) bad.push(`${k}: ${v.version} ${v.integrity} != sdk-ts ${want.version} ${want.integrity}`);
  }
  for (const name of sdk.keys()) if (!app.some(([k]) => nameOf(k) === name)) bad.push(`${name}: missing from the rewritten lock`);
  if (bad.length) {
    console.error('vendor-local-deps: SDK transitive deps drifted from sdk-ts/package-lock.json:\n  ' + bad.join('\n  '));
    process.exit(1);
  }
  console.log(`vendor-local-deps: ${seen} lock entries of ${sdk.size} SDK runtime deps match sdk-ts/package-lock.json`);
} else {
  throw new Error(`unknown mode ${mode}`);
}
