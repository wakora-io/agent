set -eu
mkdir -p /tmp/w
tar -C /tmp/w -xzf /art/opentelemetry-node.tar.gz
node /in/e2e-node-receiver.js /tmp/spans.log &
sleep 1

fetch() {
	node -e 'require("http").get("http://127.0.0.1:3007/hello",function(r){var b="";r.on("data",function(c){b+=c});r.on("end",function(){if(r.statusCode!==200||b!=="ok"){console.error("bad answer",r.statusCode,b);process.exit(1)}process.exit(0)})}).on("error",function(e){console.error(e.message);process.exit(1)})'
}

NODE_OPTIONS="--require /tmp/w/opentelemetry-node/wakora-register.js" node /in/e2e-node-app.js 3007 &
APID=$!
sleep 2
fetch
sleep 2
if [ -s /tmp/spans.log ]; then
	echo "FAIL: spans exported without OTEL_EXPORTER_OTLP_ENDPOINT (inertness broken)"
	exit 1
fi
kill $APID
wait $APID 2>/dev/null || true

OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 OTEL_SERVICE_NAME=e2e-node \
	NODE_OPTIONS="--require /tmp/w/opentelemetry-node/wakora-register.js" node /in/e2e-node-app.js 3007 &
APID=$!
sleep 4
fetch
fetch
sleep 7
grep -aq 'e2e-node' /tmp/spans.log || { echo "FAIL: no service name in exported spans"; exit 1; }
grep -aq 'GET' /tmp/spans.log || { echo "FAIL: no http server span"; exit 1; }
kill $APID 2>/dev/null || true
echo "e2e-node OK: inert without endpoint, spans exported with endpoint"
