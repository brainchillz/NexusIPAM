#!/usr/bin/env bash
# Publish-safety check: refuse if any tracked file, any commit message, or any
# historical blob contains a term from private/forbidden-terms.txt (one
# case-insensitive regex per line, '#' comments allowed).
#
# The term list is deliberately NOT on this branch — publishing a list of the
# identifiers you must never publish would defeat the point. It lives on the
# never-published `private` branch and is read straight out of it.
#
# FAILS CLOSED (exit 2). If the list cannot be loaded this refuses instead of
# reporting success: a guard that passes because its rule file went missing is
# worse than no guard, because it is the one people trust before pushing. A
# clone that genuinely has nothing to protect can set ALLOW_MISSING_TERM_LIST=1.
#
#   exit 0  checked, clean      exit 1  forbidden terms found
#   exit 2  could not check     (never confuse this with clean)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
LIST="private/forbidden-terms.txt"
# Checking out main removes the working-tree copy — tracked on `private`,
# absent here — so fall back to reading it out of that branch.
if [ -f "$LIST" ]; then
    TERMS=$(cat "$LIST")
elif git rev-parse -q --verify private >/dev/null; then
    TERMS=$(git show "private:$LIST" 2>/dev/null || true)
else
    TERMS=""
fi
PATTERN=""
if [ -n "$TERMS" ]; then
    # `|| true`: a list of nothing but comments makes grep exit 1, which under
    # `set -e` would abort here instead of reaching the check below.
    PATTERN=$(printf '%s\n' "$TERMS" | grep -v '^\s*#' | grep -v '^\s*$' \
              | paste -sd'|' - || true)
fi
if [ -z "$PATTERN" ]; then
    echo "CANNOT CHECK: $LIST is missing or defines no patterns (looked in the"
    echo "working tree and on the 'private' branch)."
    if [ "${ALLOW_MISSING_TERM_LIST:-0}" != 1 ]; then
        echo "Refusing to report a clean tree from rules that were never loaded."
        echo "If this clone has nothing to protect: ALLOW_MISSING_TERM_LIST=1 $0"
        exit 2
    fi
    echo "ALLOW_MISSING_TERM_LIST=1 set — skipping the check by request."
    exit 0
fi

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
