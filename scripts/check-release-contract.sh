#!/usr/bin/env bash
#
# Assert the release config still keeps the promises consumers pin against.
#
# This workspace is distributed by git tag, and most of its crates are pinned
# directly from other repositories. A consumer takes a tag on two assumptions it
# cannot check: that the tree it names passed the tests, and that the pin
# example it copied names a tag that exists. Both are one careless edit
# to release.toml away from being false, silently, because a release that checks
# nothing succeeds. WireTAP-Server leans on the first hard — it does not run
# wiretap-protocol's GVRET golden-byte tests in its own CI, on the grounds that
# a tag cannot name a tree where they failed.
#
# So the checks below read release.toml and hold it to what it claims.
#
# Run by the pre-release hook AND by CI, which is the only way it can catch the
# hook being deleted rather than merely weakened — nothing invoked by a hook can
# police its own existence.
#
# Safe to run by hand at any time.

set -euo pipefail

cd "$(dirname "$0")/.."

# release.toml is parsed, not pattern-matched. Both values wanted here resist a
# line-oriented read: `pre-release-hook` is an array *or* a string and may be
# written on one line or several, and `pre-release-replacements` is a list whose
# entries are told apart by their `file` key. Parsing also keeps comments out of
# the answer, so a hook that merely mentions `cargo test` in a comment cannot be
# mistaken for one that runs it.
#
# The `search` value is a regex belonging to cargo-release, which compiles it
# with the Rust regex crate. Below it is only ever handed back to grep to ask
# "does this line match the same thing cargo-release will match" — so it is
# checked for compilability first, and any answer grep cannot give is a failure
# rather than a pass.
eval "$(python3 - <<'PY'
import shlex, sys, tomllib

try:
    cfg = tomllib.load(open("release.toml", "rb"))
except (OSError, tomllib.TOMLDecodeError) as exc:
    print(f"echo {shlex.quote('  ✗ release.toml: ' + str(exc))}; exit 1")
    sys.exit(0)

hook = cfg.get("pre-release-hook", "")
hook = " ".join(hook) if isinstance(hook, list) else hook

# Disambiguated by `file`; an ambiguous set yields an empty search, which the
# check below fails on rather than guessing which entry governs the READMEs.
reps = [r for r in cfg.get("pre-release-replacements", []) if r.get("file") == "README.md"]
search = reps[0].get("search", "") if len(reps) == 1 else ""

print("hook=" + shlex.quote(hook))
print("search=" + shlex.quote(search))
PY
)"

fail=0
say_fail() { echo "  ✗ $1"; fail=1; }

# --- 1. The hook still gates on the tests -----------------------------------
#
# Presence is not gating: `cargo test || true`, `--no-run`, and a trailing `;`
# all run the tests and ignore the answer. Each is checked for by name, because
# a substring test cannot tell "runs" from "runs and discards".
if [ -z "$hook" ]; then
    say_fail "pre-release hook: release.toml has none"
elif ! grep -qE -e 'cargo test' -- <<<"$hook"; then
    say_fail "pre-release hook: does not run 'cargo test' — a tag could name a red tree,"
    echo "    and WireTAP-Server skips this workspace's tests because it cannot"
elif grep -qE -e 'cargo test[^&|;]*(\|\||--no-run|;)' -- <<<"$hook"; then
    say_fail "pre-release hook: 'cargo test' is present but does not gate the release"
else
    # release.toml calls this hook "CI parity"; hold it to all three.
    missing=""
    grep -qE -e 'cargo fmt' -- <<<"$hook" || missing="$missing fmt"
    grep -qE -e 'cargo clippy' -- <<<"$hook" || missing="$missing clippy"
    if [ -n "$missing" ]; then
        say_fail "pre-release hook: gates tests but not$missing — release.toml calls it CI parity"
    else
        echo "  ✓ pre-release hook gates on fmt, clippy and tests"
    fi
fi

# --- 2. Every README pin is in the form that gets rewritten -----------------
#
# `min = 0` on the replacement is forced: not every crate carries a pin, and a
# missing match must not fail their release. The cost is that a *malformed* pin
# — `tag="v0.15.0"`, no spaces — matches nothing, is rewritten to nothing, and
# ships a stale version behind a green release. The root README is the mirror
# image: nothing rewrites it, because replacements resolve per package and the
# workspace root is not one, so a real version there is wrong from the next
# release onward.
#
# A pin is a line carrying both a git source and a tag, so prose mentioning
# `tag =` does not block a release.
PIN='git *=.*tag *= *"'

# grep exits 2 on a pattern it cannot compile, and 1 on a clean miss. Separate
# the two once, here, so that below a miss can mean "no match" and everything
# else means the check could not be made.
search_usable=0
if [ -n "$search" ]; then
    printf '' | grep -qE -e "$search" -- && : # 0 or 1 both mean "compiled"
    [ $? -le 1 ] && search_usable=1
fi

if [ -z "$search" ]; then
    say_fail "pre-release replacements: no single README.md entry in release.toml"
elif [ "$search_usable" -ne 1 ]; then
    say_fail "pre-release replacements: search is not a usable ERE: $search"
else
    # Iterate crate *directories*, not READMEs: globbing the files means a
    # deleted README is not checked, it simply stops existing and the loop
    # never notices. Every crate owes a README; that is the point of the set.
    for dir in . crates/*/; do
        readme="${dir%/}/README.md"
        readme="${readme#./}"
        if [ ! -f "$readme" ]; then
            say_fail "$readme: missing"
            continue
        fi
        pins=$(grep -nE -e "$PIN" -- "$readme") || pins=""
        if [ "$readme" = "README.md" ]; then
            # The root's pins must be placeholders, so must NOT match $search.
            real=$(grep -E -e "$search" -- <<<"$pins") || real=""
            if [ -n "$real" ]; then
                say_fail "$readme: names a real version, and nothing rewrites the root README"
                echo "    → use the vX.Y.Z placeholder: $real"
            else
                echo "  ✓ $readme: $(grep -c . <<<"${pins:-}") pin line(s), all placeholders"
            fi
        elif [ -z "$pins" ]; then
            echo "  – $readme: no pin line"
        else
            bad=$(grep -vE -e "$search" -- <<<"$pins") || bad=""
            if [ -n "$bad" ]; then
                say_fail "$readme: a pin release.toml will not rewrite, so it goes stale silently"
                echo "    → $bad"
            else
                echo "  ✓ $readme: $(grep -c . <<<"$pins") pin line(s), all rewritable"
            fi
        fi
    done
fi

if [ "$fail" -ne 0 ]; then
    cat >&2 <<'EOF'

release.toml no longer backs what this workspace's consumers are told to expect.
Fix the config rather than the message: a pin that goes stale quietly, or a tag
cut from an untested tree, is a confident wrong answer to somebody who cannot
see this repository at all.
EOF
    exit 1
fi
