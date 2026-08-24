#!/bin/sh
# Everything CI runs, run here first.
#
# Keep this in step with .github/workflows/ci.yml. A check that exists there
# and not here will be found by a runner instead of by you.
set -e

cd "$(dirname "$0")/.."

GREEN='\033[0;32m'; RED='\033[0;31m'; DIM='\033[2m'; OFF='\033[0m'
ok()   { printf "  ${GREEN}pass${OFF}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${OFF}  %s\n" "$1"; exit 1; }
step() { printf "\n${DIM}%s${OFF}\n" "$1"; }

step "Boundaries"

if grep -qE '^\s*\.package\(' Package.swift; then
  fail "Package.swift declares a dependency. This package uses the platform and one vendored Argon2id, and nothing else."
fi
ok "no package dependencies"

hits=$(grep -rlE '^\s*(public |private |internal )?import (SwiftUI|UIKit|AppKit|WebKit|StoreKit|Combine)' \
  Sources/VaultCore Sources/VaultCrypto Sources/OTP 2>/dev/null || true)
[ -n "$hits" ] && { echo "$hits"; fail "a core module imports a UI framework"; }
ok "no UI framework in the core"

# Git does not track empty directories, so a target whose sources were never
# committed builds here and fails on a runner with an unrelated error.
missing=""
for dir in Sources/* Tests/*; do
  [ -d "$dir" ] || continue
  [ -z "$(find "$dir" -name '*.swift' -print -quit)" ] && missing="$missing $dir"
done
[ -n "$missing" ] && fail "targets with no Swift sources:$missing"
ok "every target has sources"

[ -f Tests/ConformanceTests/Vectors/manifest.json ] \
  || fail "the vector corpus is missing — run Scripts/sync-vectors.sh"
ok "corpus present ($(find Tests/ConformanceTests/Vectors -type f | wc -l | tr -d ' ') files)"

step "Build and test"

# Clean first. Changing a memberwise initialiser rewrites its mangled symbol,
# and SwiftPM has been seen to leave dependent test objects linked against the
# old one. A runner always starts clean, so only a local run can hit this.
swift package clean
swift build >/dev/null || fail "build"
ok "builds"

swift test >/dev/null 2>&1 || { swift test 2>&1 | grep -E 'error:|failed' | head -20; fail "tests"; }
ok "tests pass"

printf "\n${GREEN}Everything CI runs passes here. Safe to push.${OFF}\n"
