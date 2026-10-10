set -eu
VER="${1:?usage: inner-node.sh <otel-node-version>}"
B=/tmp/opentelemetry-node
mkdir -p "$B"
cd "$B"
cp /in/node/package.json /in/node/package-lock.json "$B/"
if ! grep -q "\"@opentelemetry/auto-instrumentations-node\":\"$VER\"" package.json; then
  echo "packaging/apm/node pins another version than $VER - regenerate its package.json and package-lock.json" >&2
  exit 1
fi
npm ci --omit=dev --no-audit --no-fund --loglevel=error
cp /in/wakora-register.js "$B/"
node -e 'require("/tmp/opentelemetry-node/wakora-register.js"); console.log("inert require ok")'
tar -C /tmp/opentelemetry-node -czf /out/opentelemetry-node.tar.gz .
ls -la /out/opentelemetry-node.tar.gz
