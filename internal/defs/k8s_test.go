package defs

import "testing"

func TestParseKubeconfig(t *testing.T) {
	raw := `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: Y2FkYXRh
    server: https://127.0.0.1:6443
  name: default
users:
- user:
    client-certificate-data: Y2VydGRhdGE=
    client-key-data: a2V5ZGF0YQ==
`
	server, ca, cert, key := parseKubeconfig(raw)
	if server != "https://127.0.0.1:6443" {
		t.Fatalf("server: %q", server)
	}
	if string(ca) != "cadata" || string(cert) != "certdata" || string(key) != "keydata" {
		t.Fatalf("pem blobs: %q %q %q", ca, cert, key)
	}
}

func TestParseCPUMilli(t *testing.T) {
	cases := map[string]float64{
		"250m": 250, "1": 1000, "2500000n": 2.5, "1500u": 1.5, "": 0,
	}
	for in, want := range cases {
		if got := parseCPUMilli(in); got != want {
			t.Fatalf("parseCPUMilli(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseMemBytes(t *testing.T) {
	cases := map[string]float64{
		"128Ki": 131072, "2Mi": 2097152, "1Gi": 1073741824, "1000": 1000, "5M": 5e6,
	}
	for in, want := range cases {
		if got := parseMemBytes(in); got != want {
			t.Fatalf("parseMemBytes(%q) = %v, want %v", in, got, want)
		}
	}
}
