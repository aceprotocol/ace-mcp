#!/usr/bin/env bash
# Make the package installable inside `docker build`, where the sibling checkout
# behind `file:../sdk-ts` does not exist.
#
#   - `npm pack`s ../sdk-ts (a runtime dependency) into vendor/*.tgz and points
#     `@ace-protocol/sdk` at the tarball;
#   - pins the SDK's transitive runtime deps (@noble/* — every
#     non-dev `node_modules/…` entry of sdk-ts's package-lock.json) with exact-version
#     `overrides` in the target package.json, so the image gets the versions the SDK
#     was tested with instead of whatever the registry resolves at build time. (npm
#     does not honour a shrinkwrap inside a `file:` tarball here, so overrides it is.)
#   - refreshes package-lock.json to match (no install, no scripts), then asserts, as a
#     backstop, that every lock entry of those packages has the same version +
#     integrity as in sdk-ts's package-lock.json (exit 1 otherwise).
#
# It REWRITES package.json and package-lock.json in the target directory. Run it
# in CI on a fresh checkout, or locally on a scratch copy:
#   scripts/vendor-local-deps.sh [target-dir]      # default: the repo root
# Undo locally with: git checkout package.json package-lock.json && rm -rf vendor
#
# Prerequisite: ../sdk-ts is built (`npm ci && npm run build` there); its
# package.json ships only dist/, and it has no prepare script.
# Goes away at the formal release, when @ace-protocol/sdk is on npm.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="$(cd "${1:-$repo_root}" && pwd)"
sdk_dir="${SDK_TS_DIR:-$repo_root/../sdk-ts}"

[ -f "$target/package.json" ] || { echo "vendor-local-deps: no package.json in $target" >&2; exit 1; }
[ -d "$sdk_dir" ] || { echo "vendor-local-deps: sdk-ts not found at $sdk_dir (set SDK_TS_DIR)" >&2; exit 1; }
sdk_dir="$(cd "$sdk_dir" && pwd)"
[ -f "$sdk_dir/dist/index.js" ] || { echo "vendor-local-deps: $sdk_dir is not built (run npm ci && npm run build there)" >&2; exit 1; }

[ -f "$sdk_dir/package-lock.json" ] || { echo "vendor-local-deps: $sdk_dir has no package-lock.json" >&2; exit 1; }

mkdir -p "$target/vendor"
rm -f "$target"/vendor/ace-protocol-sdk-*.tgz

tarball="$(cd "$sdk_dir" && npm pack --silent --ignore-scripts --pack-destination "$target/vendor" | tail -n 1)"
echo "vendor-local-deps: packed $tarball"

(
  cd "$target"
  node "$repo_root/scripts/vendor-lock.mjs" rewrite "$sdk_dir/package-lock.json" "$tarball"
  npm install --package-lock-only --ignore-scripts --no-audit --no-fund
)
node "$repo_root/scripts/vendor-lock.mjs" verify "$sdk_dir/package-lock.json" "$target/package-lock.json"
echo "vendor-local-deps: @ace-protocol/sdk -> file:vendor/$tarball (transitive deps pinned by overrides)"
