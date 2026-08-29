package apm

import "testing"

func TestFoldSpeedscope(t *testing.T) {
	data := []byte(`{
	  "shared": {"frames": [{"name": "Main"}, {"name": "Handler;X"}, {"name": "Query"}]},
	  "profiles": [{
	    "type": "evented",
	    "events": [
	      {"type": "O", "frame": 0, "at": 0},
	      {"type": "O", "frame": 1, "at": 10},
	      {"type": "O", "frame": 2, "at": 20},
	      {"type": "C", "frame": 2, "at": 45},
	      {"type": "C", "frame": 1, "at": 50},
	      {"type": "C", "frame": 0, "at": 60}
	    ]
	  }]
	}`)
	folded, total, threads, err := FoldSpeedscope(data)
	if err != nil {
		t.Fatal(err)
	}
	if total != 60 || threads != 1 {
		t.Fatalf("total ms = %v threads = %d, want 60/1", total, threads)
	}
	if folded["Main"] != 20 {
		t.Fatalf("Main self = %d, want 20 (10 pre + 10 post child)", folded["Main"])
	}
	if folded["Main;Handler,X"] != 15 {
		t.Fatalf("Handler self = %d, want 15 (folded: %v)", folded["Main;Handler,X"], folded)
	}
	if folded["Main;Handler,X;Query"] != 25 {
		t.Fatalf("Query self = %d, want 25", folded["Main;Handler,X;Query"])
	}
}

func TestFoldSpeedscopeStripsSyntheticFrames(t *testing.T) {
	data := []byte(`{
	  "shared": {"frames": [
	    {"name": "Process64 w3wp (7940) Args: -ap x"},
	    {"name": "(Non-Activities)"},
	    {"name": "Threads"},
	    {"name": "Thread (11276)"},
	    {"name": "App!Real.Work()"}
	  ]},
	  "profiles": [{
	    "type": "evented",
	    "events": [
	      {"type": "O", "frame": 0, "at": 0},
	      {"type": "O", "frame": 1, "at": 0},
	      {"type": "O", "frame": 2, "at": 0},
	      {"type": "O", "frame": 3, "at": 0},
	      {"type": "O", "frame": 4, "at": 30},
	      {"type": "C", "frame": 4, "at": 80},
	      {"type": "C", "frame": 3, "at": 100},
	      {"type": "C", "frame": 2, "at": 100},
	      {"type": "C", "frame": 1, "at": 100},
	      {"type": "C", "frame": 0, "at": 100}
	    ]
	  }]
	}`)
	folded, total, _, err := FoldSpeedscope(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(folded) != 1 {
		t.Fatalf("want only the real frame stack, got %v", folded)
	}
	if folded["App!Real.Work()"] != 50 {
		t.Fatalf("real work = %d, want 50 (synthetic-only intervals dropped)", folded["App!Real.Work()"])
	}
	if total != 50 {
		t.Fatalf("total = %v, want 50", total)
	}
}

func TestParseDotnetTracePS(t *testing.T) {
	out := " 1234  w3wp       C:\\Windows\\System32\\inetsrv\\w3wp.exe\n" +
		" 5678  dotnet     /usr/bin/dotnet /srv/app.dll\n" +
		"garbage line\n"
	if got := ParseDotnetTracePS(out, "w3wp"); len(got) != 1 || got[0] != 1234 {
		t.Fatalf("w3wp filter: %v", got)
	}
	if got := ParseDotnetTracePS(out, ""); len(got) != 2 {
		t.Fatalf("no filter: %v", got)
	}
}

func TestDotnetTraceName(t *testing.T) {
	if n := DotnetTraceName("linux-glibc", "amd64"); n != "dotnet-trace-linux-glibc-amd64" {
		t.Fatalf("name: %s", n)
	}
	if n := DotnetTraceName("", "amd64"); n != "" {
		t.Fatalf("empty osTag should give empty name, got %s", n)
	}
}
