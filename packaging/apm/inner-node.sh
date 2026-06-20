set -eu
VER="${1:?usage: inner-node.sh <otel-node-version>}"
B=/tmp/opentelemetry-node
mkdir -p "$B"
cd "$B"
printf '{"name":"wakora-otel-node","private":true,"dependencies":{"@opentelemetry/auto-instrumentations-node":"%s"}}\n' "$VER" > package.json
npm install --omit=dev --no-audit --no-fund --loglevel=error
cp /in/wakora-register.js "$B/"
node -e 'require("/tmp/opentelemetry-node/wakora-register.js"); console.log("inert require ok")'
tar -C /tmp/opentelemetry-node -czf /out/opentelemetry-node.tar.gz .
ls -la /out/opentelemetry-node.tar.gz
