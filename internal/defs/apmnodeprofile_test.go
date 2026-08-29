//go:build linux

package defs

import "testing"

const perfScriptSample = `node 1469045 75908.695600:   10101010 task-clock:ppp: 
	    7f0935280e4c [unknown] (/usr/lib/x86_64-linux-gnu/libnode.so.109)
	    7f08b5445380 Function:^ node:internal/per_context/primordials:376+0x80 (/tmp/perf-1469045.map)
	    7f093553b988 v8::internal::Execution::Call(v8::internal::Isolate*)+0x78 (/usr/lib/x86_64-linux-gnu/libnode.so.109)
	    7f0934f286d3 node::SpinEventLoop(node::Environment*)+0x1b3 (/usr/lib/x86_64-linux-gnu/libnode.so.109)

node 1469045 75908.737997:   10101010 task-clock:ppp: 
	    7f0934f286d3 node::SpinEventLoop(node::Environment*)+0x1b3 (/usr/lib/x86_64-linux-gnu/libnode.so.109)
	    7f0935054213 node::NodeMainInstance::Run()+0xa3 (/usr/lib/x86_64-linux-gnu/libnode.so.109)

node 1469045 75908.747997:   10101010 task-clock:ppp: 
	    7f0935280e4c [unknown] (/usr/lib/x86_64-linux-gnu/libnode.so.109)
`

func TestFoldPerfScript(t *testing.T) {
	folded, total, hits := foldPerfScript(perfScriptSample)
	if total != 3 {
		t.Fatalf("total = %d", total)
	}
	if hits != 2 {
		t.Fatalf("hits = %d (unknown-only sample must not count)", hits)
	}
	want := "node::SpinEventLoop(node::Environment*);v8::internal::Execution::Call(v8::internal::Isolate*);node:internal/per_context/primordials:376"
	if folded[want] != 1 {
		t.Fatalf("folded stacks: %v", folded)
	}
	want2 := "node::NodeMainInstance::Run();node::SpinEventLoop(node::Environment*)"
	if folded[want2] != 1 {
		t.Fatalf("second stack missing: %v", folded)
	}
}

func TestPerfFrameSymbol(t *testing.T) {
	cases := map[string]string{
		"	    7f0934f286d3 node::SpinEventLoop(node::Environment*)+0x1b3 (/usr/lib/libnode.so)":   "node::SpinEventLoop(node::Environment*)",
		"	    7f08b5445380 Function:^ node:internal/bootstrap:12+0x80 (/tmp/perf-1.map)":          "node:internal/bootstrap:12",
		"	    7f08b5445380 Function:* handleRequest /opt/app/server.js:42+0x10 (/tmp/perf-1.map)": "handleRequest /opt/app/server.js:42",
		"	    7f0935280e4c [unknown] (/usr/lib/libnode.so)":                                       "",
		"": "",
	}
	for in, want := range cases {
		if got := perfFrameSymbol(in); got != want {
			t.Fatalf("perfFrameSymbol(%q) = %q, want %q", in, got, want)
		}
	}
}
