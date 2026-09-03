#!/usr/bin/env bash
#
# End-to-end walkthrough of the model-release provenance ledger.
#
# Builds the example, proves the lineage, shows that retention protects it from
# collection, then tampers with a chunk on disk and shows verification catching
# it. Every step is a real command against a real data directory.
#
#   ./scripts/demo.sh            # run it
#   ./scripts/demo.sh --keep     # keep the data directory and print its path
#
set -euo pipefail

cd "$(dirname "$0")/.."

KEEP=false
[[ "${1:-}" == "--keep" ]] && KEEP=true

DATA_DIR="$(mktemp -d)"
cleanup() {
  if [[ "$KEEP" == true ]]; then
    echo
    echo "data directory kept at $DATA_DIR"
    echo "  dag --data-dir $DATA_DIR serve"
  else
    rm -rf "$DATA_DIR"
  fi
}
trap cleanup EXIT

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { printf '\033[2m$ %s\033[0m\n' "$*"; }

bold "Building"
cargo build --locked --release --quiet
DAG="$PWD/target/release/dag --data-dir $DATA_DIR"

bold "1. Load the worked example"
step "dag usecase seed"
$DAG usecase seed

bold "2. Recover a release's complete lineage from its name alone"
step "dag usecase verify"
$DAG usecase verify

bold "3. The dataset pointer's history is the audit trail"
step "dag pointer history --id datasets/customer-transactions"
$DAG pointer history --id datasets/customer-transactions

bold "4. Each run records exactly which revisions it read"
step "dag job runs --job-id attest-release"
$DAG job runs --job-id attest-release

bold "5. Retention: the release subtree is protected, scratch data is not"
step "dag pin list --active-only"
$DAG pin list --active-only

RELEASE_CID=$($DAG pointer resolve --id models/fraud-detector/production)
step "dag gc status --cid \$(dag pointer resolve --id models/fraud-detector/production)"
$DAG gc status --cid "$RELEASE_CID"

bold "6. Collection honours it"
step "dag gc run --dry-run --min-age-secs 0"
$DAG gc run --dry-run --min-age-secs 0

bold "7. Recovery gate: a fresh deployment refuses to collect"
FRESH="$(mktemp -d)"
step "dag --data-dir <fresh> gc run --dry-run"
# Capture first: with `set -o pipefail` a non-zero `dag` would fail the
# pipeline even when grep matched, which is exactly the case being tested.
GC_OUTPUT=$("$PWD/target/release/dag" --data-dir "$FRESH" gc run --dry-run 2>&1 || true)
echo "  $GC_OUTPUT"
if grep -q "recovery not complete" <<<"$GC_OUTPUT"; then
  echo "  refused, as it should: retention has not been rebuilt from the pin log"
else
  echo "  UNEXPECTED: collection ran without recovery" >&2
  exit 1
fi
rm -rf "$FRESH"

bold "8. Tamper with a chunk on disk; verification catches it"
CONFIG_CID=$($DAG pointer resolve --id configs/fraud-detector)
CHUNK_PATH="$DATA_DIR/data/${CONFIG_CID:0:2}/${CONFIG_CID:2}"
step "printf 'tampered' > \$CHUNK_PATH"
printf 'tampered' > "$CHUNK_PATH"

step "dag usecase verify"
if $DAG usecase verify; then
  echo "  UNEXPECTED: verification passed on tampered data" >&2
  exit 1
else
  echo
  echo "  verification failed, as it should — the config no longer hashes to its CID"
fi

bold "Done"
cat <<'EOF'
What this showed:

  content addressing   the CID is the hash, so tampering is detectable by anyone
  entries and links    lineage is traversable from the data, not a side database
  pointers             mutable names with an append-only history
  jobs                 inputs resolved and recorded at trigger time
  pins                 a subtree pin retains everything a release depends on
  recovery gate        collection refuses to run against a half-rebuilt index
  events               every step above emitted to one ordered journal

Explore it in a browser:

  dag usecase seed && dag serve
EOF
