#!/usr/bin/env bash
# Standalone non-regression: run the historical engine (BASE commit) and the current engine on the same lab
# target with the same YAML configuration, then compare every exported artefact (timestamps/ids normalised).
# Runs on the integration VM (Docker). Usage: tests/regression/run.sh [BASE_COMMIT]   (default: first parent of feature branch = main)
set -euo pipefail
cd "$(dirname "$0")/../.."
BASE="${1:-$(git merge-base HEAD main)}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/base"
git archive "$BASE" tls_scanner tls_scan.py | tar -x -C "$tmp/base"
echo "Baseline engine: $BASE"
ops/dev/vm.sh >/dev/null
HOST="${VM_HOST:-vm-integrations}"; DEST="${VM_DEST:-/home/cdev/tlsscan-dev}"
rsync -rlz --delete "$tmp/base/" "$HOST:$DEST/.regression-base/"
ssh "$HOST" "cd $DEST && bash -s" <<REMOTE
set -euo pipefail
docker build -q -t tlsscan-regression -f ops/docker/backend.Dockerfile --build-arg WITH_DEV=true . >/dev/null
docker build -q -t tlsscan-lab -f tests/lab/lab-tls.Dockerfile . >/dev/null
docker network rm tlsscan-regress >/dev/null 2>&1 || true
docker network create tlsscan-regress >/dev/null
trap 'docker rm -f regress-lab >/dev/null 2>&1; docker network rm tlsscan-regress >/dev/null 2>&1; docker run --rm -v \$PWD:/w alpine rm -rf /w/.regression-out' EXIT
docker run -d --rm --name regress-lab --network tlsscan-regress --network-alias lab-tls tlsscan-lab >/dev/null
sleep 4
rm -rf .regression-out; mkdir -p .regression-out/base .regression-out/new; chmod 777 .regression-out/base .regression-out/new
run() { # run <tree> <outdir>
  docker run --rm --network tlsscan-regress -u \$(id -u):\$(id -g) -e HOME=/tmp -v "\$PWD/\$1:/app" -v "\$PWD/tests/regression/config:/app/config:ro" \
    -v "\$PWD/.regression-out/\$2:/out" -w /app -e PYTHONPATH=/app tlsscan-regression python tls_scan.py --config config/config.yaml --report lab_regression >/dev/null
}
run .regression-base base
run . new
python3 - <<'PY'
import json, pathlib, re, sys
out = pathlib.Path(".regression-out")
def norm(text):
    text = re.sub(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:?\d\d)?", "<TS>", text)
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<UUID>", text)
    text = re.sub(r"\d{4}-\d\d-\d\d-\d{6}", "<STAMP>", text)
    text = re.sub(r"tls-scan-pki-[a-z0-9_]+", "tls-scan-pki-<TMP>", text)
    text = re.sub(r"(?i)(duration[^\n|]*?)\d+(\.\d+)?", r"\1<N>", text)
    text = re.sub(r"\d+ days?", "<N> days", text)
    return text
def files(root):
    return {str(p.relative_to(root)): p for p in sorted(root.rglob("*")) if p.is_file() and "assets" not in p.parts}
base, new = files(out / "base"), files(out / "new")
fail = False
def names(d):
    return {re.sub(r"\d{4}-\d\d-\d\d-\d{6}", "<STAMP>", k) for k in d}
if names(base) != names(new):
    print("FILE SET DIFFERS:", names(base) ^ names(new)); fail = True
by_norm = lambda d: {re.sub(r"\d{4}-\d\d-\d\d-\d{6}", "<STAMP>", k): v for k, v in d.items()}
b, n = by_norm(base), by_norm(new)
for k in sorted(set(b) & set(n)):
    x, y = norm(b[k].read_text(errors="replace")), norm(n[k].read_text(errors="replace"))
    if x != y:
        import difflib
        print("DIFF in", k); print("\n".join(l[:240] for l in list(difflib.unified_diff(x.splitlines(), y.splitlines(), lineterm="", n=0))[:12])); fail = True
    else:
        print("identical:", k)
print("assets copied:", sorted({str(p.relative_to(out/'new')) for p in (out/'new').rglob('assets/**/*') if p.is_file()}) == sorted({str(p.relative_to(out/'base')) for p in (out/'base').rglob('assets/**/*') if p.is_file()}))
sys.exit(1 if fail else 0)
PY
REMOTE
