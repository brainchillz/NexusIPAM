#!/usr/bin/env bash
# Publish-safety check: refuse if any tracked file, any commit message, or any
# historical blob contains a term from private/forbidden-terms.txt (one
# case-insensitive regex per line, '#' comments allowed).
#
# The term list is deliberately NOT committed — publishing a list of the
# identifiers you must never publish would defeat the point. Run this before
# any push to a public remote; without the list file there is nothing to
# check and it exits clean, so public clones are unaffected.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
LIST="private/forbidden-terms.txt"
[ -f "$LIST" ] || { echo "no $LIST — nothing to check"; exit 0; }
PATTERN=$(grep -v '^\s*#' "$LIST" | grep -v '^\s*$' | paste -sd'|' -)
[ -n "$PATTERN" ] || { echo "empty term list"; exit 0; }

fail=0
if git grep -I -i -n -E "$PATTERN" -- . >/tmp/pubcheck.$$ 2>/dev/null; then
    echo "FORBIDDEN TERMS in tracked files:"; cat /tmp/pubcheck.$$; fail=1
fi
# HEAD only, deliberately: private-only branches (never pushed to a public
# remote) are allowed to hold internal notes. Run this ON the branch you are
# about to publish.
if git log HEAD --format='%h %s%n%b' | grep -i -n -E "$PATTERN" >/tmp/pubcheck.$$; then
    echo "FORBIDDEN TERMS in commit messages:"; cat /tmp/pubcheck.$$; fail=1
fi
# Historical blobs: a term scrubbed from HEAD but present in an old commit
# still publishes. Small repo — brute force is fine.
if git log HEAD -p | grep -i -E "$PATTERN" | head -20 | grep -q .; then
    echo "FORBIDDEN TERMS in historical diffs (git log -p | grep ...):"
    git log HEAD -p | grep -i -n -E "$PATTERN" | head -10; fail=1
fi
rm -f /tmp/pubcheck.$$
[ "$fail" = 0 ] && echo "clean: tree, messages and history"
exit $fail
