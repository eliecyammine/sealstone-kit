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

# This repository is public, and what is open is exactly what somebody needs in
# order to verify the trust claims and decode their own data. The Map engine,
# the service knowledge base, the applications and the relay are the business
# and stay closed.
#
# That rule was written down and broken anyway: a RecoveryMap target was added
# here, and it was the whole of layer 2. Nothing caught it, because nothing was
# looking. A new target is now a deliberate act — add it below, having decided
# that a stranger reading it learns nothing but how to open their own file.
OPEN_TARGETS="VaultCore VaultCrypto VaultStore OTP ImportExport"
for dir in Sources/*; do
  [ -d "$dir" ] || continue
  name=$(basename "$dir")
  case " $OPEN_TARGETS " in
    *" $name "*) ;;
    *) fail "$name is not on the list of targets this public repository may hold. If it belongs here, add it to OPEN_TARGETS and say why in the commit; if it is product logic, it belongs in the private repository." ;;
  esac
done
ok "only the open targets are here"

# The target allowlist catches a new target. It does not catch the service
# knowledge base being dropped into an existing one, which is the easier
# mistake to make and the more valuable thing to leak: the catalogue is the
# part that took the longest to assemble and the part a competitor would copy
# first, and nothing in it is load-bearing for the trust argument.
leaked=$(find Sources Tests -iname 'services.json' -o -iname 'servicecatalog*' \
  -o -iname 'serviceknowledge*' 2>/dev/null || true)
[ -n "$leaked" ] && { echo "$leaked"; fail "the service knowledge base does not belong in the public repository"; }

# And the mechanism it would arrive by. The one legitimate resource here is the
# conformance corpus, which is a test fixture and is published on purpose: it
# is how somebody checks their own implementation against this one. A shipping
# target carrying data is the shape the knowledge base would take.
bundled=$(grep -n 'resources:' Package.swift | grep -v '\.copy("Vectors")' || true)
[ -n "$bundled" ] && { echo "$bundled"; fail "a target other than the conformance corpus declares bundled resources — the open targets ship code, not data"; }
ok "no service knowledge here"

step "Build and test"

# Clean first. Changing a memberwise initialiser rewrites its mangled symbol,
# and SwiftPM has been seen to leave dependent test objects linked against the
# old one. A runner always starts clean, so only a local run can hit this.
swift package clean
swift build >/dev/null || fail "build"
ok "builds"

# The same environment CI uses. Without this the Argon2 vectors and the
# conformance corpus run at cheap parameters here and at shipping ones there,
# which is the difference between a green local run and a red push.
export SEALSTONE_SLOW_TESTS=1

swift test >/dev/null 2>&1 || { swift test 2>&1 | grep -E 'error:|failed' | head -20; fail "tests"; }
ok "tests pass, at shipping parameters"

printf "\n${GREEN}Everything CI runs passes here. Safe to push.${OFF}\n"
