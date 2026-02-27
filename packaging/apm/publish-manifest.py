#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import time

apmDir = "/var/lib/wakora-release/apm"
meta = dict(kv.split("=", 1) for kv in sys.argv[1:])

artifacts = []
for f in sorted(os.listdir(apmDir)):
    isTool = f.startswith("dotnet-trace-")
    if not (f.endswith(".tar.gz") or f.endswith(".so") or isTool):
        continue
    p = os.path.join(apmDir, f)
    digest = hashlib.sha256(open(p, "rb").read()).hexdigest()
    name = f[:-7] if f.endswith(".tar.gz") else f
    artifacts.append({"name": name, "file": f, "sha256": digest, "size": os.path.getsize(p)})

manifest = {
    "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "upstream": meta,
    "artifacts": artifacts,
}
with open(os.path.join(apmDir, "manifest.json"), "w") as out:
    json.dump(manifest, out, indent=1)
print("manifest: %d artifacts" % len(artifacts))
