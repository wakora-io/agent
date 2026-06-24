package doctor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wakora.io/agent/internal/buildinfo"
)

type State int

const (
	Ok State = iota
	Warn
	Fail
	Info
	Skip
)

func (s State) Label() string {
	switch s {
	case Ok:
		return "ok"
	case Warn:
		return "warn"
	case Fail:
		return "FAIL"
	case Info:
		return "info"
	default:
		return "skipped"
	}
}

type Check struct {
	Name   string
	State  State
	Detail string
	Next   string
}

type Input struct {
	ConfigDir   string
	StateDir    string
	LogPath     string
	Endpoint    string
	Pin         string
	ConfPin     string
	ServerID    string
	Key         string
	IdentityErr error
	HTTP        *http.Client
}

type status struct {
	ConnectedNow  bool   `json:"connectedNow"`
	LastConnectAt int64  `json:"lastConnectAt"`
	LastAckAt     int64  `json:"lastAckAt"`
	LastError     string `json:"lastError"`
	RingPending   int64  `json:"ringPending"`
	WrittenAt     int64  `json:"writtenAt"`
}

func Run(in Input) []Check {
	var out []Check
	out = append(out, checkAgent(in))
	out = append(out, checkService())
	out = append(out, checkDisk(in))

	id := checkIdentity(in)
	out = append(out, id)

	host, port := hostPort(in.Endpoint)
	dns := checkDNS(host)
	out = append(out, dns)
	if dns.State == Fail {
		out = append(out, skip("tcp "+port, "blocked by dns"), skip("tls", "blocked by dns"), skip("clock", "blocked by dns"), skip("auth", "blocked by dns"), skip("data flow", "blocked by dns"))
		return out
	}

	tcp := checkTCP(host, port)
	out = append(out, tcp)
	if tcp.State == Fail {
		out = append(out, skip("tls", "blocked by tcp"), skip("clock", "blocked by tcp"), skip("auth", "blocked by tcp"), skip("data flow", "blocked by tcp"))
		return out
	}

	tlsc := checkTLS(host, port, in.Pin)
	out = append(out, tlsc)
	out = append(out, checkClock(in))

	auth, flow := checkAuthFlow(in, id)
	out = append(out, auth, flow)
	return out
}

func Render(checks []Check) string {
	var b strings.Builder
	for _, c := range checks {
		fmt.Fprintf(&b, "  %-11s %-8s %s\n", c.Name, c.State.Label(), c.Detail)
		if c.Next != "" && (c.State == Fail || c.State == Warn) {
			for _, ln := range wrap(c.Next, 66) {
				fmt.Fprintf(&b, "  %-11s %-8s -> %s\n", "", "", ln)
			}
		}
	}
	return b.String()
}

func Worst(checks []Check) State {
	worst := Ok
	for _, c := range checks {
		if c.State == Fail {
			return Fail
		}
		if c.State == Warn && worst != Fail {
			worst = Warn
		}
	}
	return worst
}

func wrap(s string, w int) []string {
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, word := range words {
		if cur == "" {
			cur = word
		} else if len(cur)+1+len(word) <= w {
			cur += " " + word
		} else {
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func checkAgent(in Input) Check {
	detail := buildinfo.Version
	if in.ConfPin != "" {
		detail += " (pinned at " + in.ConfPin + ")"
	} else {
		detail += " (channel stable, not pinned)"
	}
	return Check{Name: "agent", State: Ok, Detail: detail}
}

func checkDisk(in Input) Check {
	dir := in.StateDir
	if dir == "" {
		dir = "/var/lib/wakora"
	}
	testFile := filepath.Join(dir, ".doctor-write")
	if err := os.WriteFile(testFile, []byte("x"), 0o600); err != nil {
		return Check{Name: "disk", State: Fail, Detail: dir + " not writable: " + err.Error(),
			Next: "free space or fix permissions on " + dir + " so the agent can spool and stage"}
	}
	os.Remove(testFile)
	free := freeBytes(dir)
	ring := ringBytes(in.StateDir)
	detail := dir + " writable"
	if free > 0 {
		detail += ", " + humanBytes(free) + " free"
	}
	if ring == 0 {
		detail += ", spool empty"
	} else {
		detail += ", " + humanBytes(ring) + " spooled (offline backlog)"
	}
	st := Ok
	next := ""
	if free > 0 && free < 200<<20 {
		st = Warn
		next = "less than 200 MB free - the spool and staged artifacts may not fit"
	}
	return Check{Name: "disk", State: st, Detail: detail, Next: next}
}

func checkIdentity(in Input) Check {
	idPath := filepath.Join(in.ConfigDir, "identity")
	fi, err := os.Stat(idPath)
	if err != nil {
		return Check{Name: "identity", State: Warn, Detail: "not registered",
			Next: "register this host: wakora --key <TEAMKEY>"}
	}
	_ = fi
	if f, err := os.Open(idPath); err != nil {
		return Check{Name: "identity", State: Warn, Detail: "present but this user cannot read it",
			Next: "run as root: sudo wakora doctor"}
	} else {
		f.Close()
	}
	if in.IdentityErr != nil {
		return Check{Name: "identity", State: Fail, Detail: "sealed to this machine and no longer decryptable",
			Next: "the hardware or the root seed changed - re-register: wakora --key <TEAMKEY>"}
	}
	if in.ServerID == "" {
		return Check{Name: "identity", State: Warn, Detail: "not registered",
			Next: "register this host: wakora --key <TEAMKEY>"}
	}
	short := in.ServerID
	if len(short) > 8 {
		short = short[:8]
	}
	return Check{Name: "identity", State: Ok, Detail: "uuid " + short + "..., registered"}
}

func checkDNS(host string) Check {
	if host == "" {
		return Check{Name: "dns", State: Fail, Detail: "no gateway endpoint built into this binary",
			Next: "reinstall from get.wakora.io (endpoint is baked at build)"}
	}
	if net.ParseIP(host) != nil {
		return Check{Name: "dns", State: Ok, Detail: host + " (literal ip)"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return Check{Name: "dns", State: Fail, Detail: host + " does not resolve",
			Next: "this box cannot resolve the gateway - check /etc/resolv.conf and outbound DNS"}
	}
	return Check{Name: "dns", State: Ok, Detail: host + " -> " + ips[0]}
}

func checkTCP(host, port string) Check {
	start := time.Now()
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return Check{Name: "tcp " + port, State: Fail, Detail: "cannot connect: " + err.Error(),
			Next: "a firewall likely blocks outbound tcp " + port + " - ask IT to allow " + host + ":" + port}
	}
	conn.Close()
	return Check{Name: "tcp " + port, State: Ok, Detail: fmt.Sprintf("%dms", time.Since(start).Milliseconds())}
}

func checkTLS(host, port, pin string) Check {
	if pin == "" {
		return Check{Name: "tls", State: Info, Detail: "no pin built in (dev build) - skipping pin verification"}
	}
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return Check{Name: "tls", State: Fail, Detail: "handshake failed: " + err.Error(),
			Next: "tls to the gateway failed - a proxy or firewall may be interfering"}
	}
	defer conn.Close()
	want, _ := base64.StdEncoding.DecodeString(pin)
	for _, cert := range conn.ConnectionState().PeerCertificates {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if want != nil && subtle(sum[:], want) {
			return Check{Name: "tls", State: Ok, Detail: "server key matches the pinned key"}
		}
	}
	return Check{Name: "tls", State: Fail, Detail: "server key does not match the pinned key",
		Next: "something on this network intercepts TLS (corporate proxy/DPI). The agent refuses such connections by design. Ask IT to exempt " + host + ":" + port + " from inspection"}
}

func checkClock(in Input) Check {
	base := httpsBase(in.Endpoint)
	if base == "" || in.HTTP == nil {
		return Check{Name: "clock", State: Skip, Detail: "no gateway reference"}
	}
	req, err := http.NewRequest(http.MethodHead, base+"/release/", nil)
	if err != nil {
		return Check{Name: "clock", State: Skip, Detail: "no gateway reference"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp, err := in.HTTP.Do(req.WithContext(ctx))
	if err != nil {
		return Check{Name: "clock", State: Skip, Detail: "gateway did not answer for a time reference"}
	}
	resp.Body.Close()
	ds := resp.Header.Get("Date")
	if ds == "" {
		return Check{Name: "clock", State: Skip, Detail: "no Date header from the gateway"}
	}
	srv, err := http.ParseTime(ds)
	if err != nil {
		return Check{Name: "clock", State: Skip, Detail: "unparseable gateway time"}
	}
	off := time.Since(srv)
	if off < 0 {
		off = -off
	}
	human := fmt.Sprintf("offset %+.1fs", time.Since(srv).Seconds())
	if off >= 60*time.Second {
		return Check{Name: "clock", State: Fail, Detail: human,
			Next: "the system clock is far off - enable NTP (timedatectl set-ntp true). Skew breaks ordering and can drop data"}
	}
	if off >= 5*time.Second {
		return Check{Name: "clock", State: Warn, Detail: human, Next: "clock drift - enable NTP to keep timestamps honest"}
	}
	return Check{Name: "clock", State: Ok, Detail: human}
}

func checkAuthFlow(in Input, id Check) (Check, Check) {
	if id.State != Ok {
		return skip("auth", "no identity"), skip("data flow", "no identity")
	}
	st, ok := readStatus(in.StateDir)
	if !ok {
		return Check{Name: "auth", State: Info, Detail: "not reported by the running agent",
				Next: "the agent is not running or predates status reporting - the console shows this host's last-seen; start it: wakora service start"},
			skip("data flow", "no status from the agent")
	}
	if st.ConnectedNow {
		return Check{Name: "auth", State: Ok, Detail: "the running agent holds an authenticated connection"}, flowFromStatus(st)
	}
	switch st.LastError {
	case "deregistered":
		return Check{Name: "auth", State: Warn, Detail: "this host was removed from the console (410) - the agent is idle",
				Next: "re-enroll with wakora --key <TEAMKEY>, or run wakora uninstall to clean up"},
			skip("data flow", "host removed from the console")
	case "unauthorized":
		return Check{Name: "auth", State: Fail, Detail: "the gateway rejected the per-server key (401)",
				Next: "the key was revoked or rotated out - re-register: wakora --key <TEAMKEY>"},
			skip("data flow", "not authenticated")
	case "":
		return Check{Name: "auth", State: Warn, Detail: "the agent is not connected right now",
				Next: "start it: wakora service start (the network checks above show the path is fine)"},
			flowFromStatus(st)
	default:
		return Check{Name: "auth", State: Warn, Detail: "last connection error: " + st.LastError,
				Next: "see the network checks above; start the service: wakora service start"},
			skip("data flow", "not connected")
	}
}

func flowFromStatus(st status) Check {
	if st.LastAckAt <= 0 {
		return Check{Name: "data flow", State: Warn, Detail: "connected, no delivery acked yet"}
	}
	ago := time.Since(time.Unix(st.LastAckAt, 0))
	human := "last ack " + humanAgo(ago)
	if st.RingPending > 0 {
		human += ", " + humanBytes(st.RingPending) + " spooled"
	}
	if ago > 5*time.Minute {
		return Check{Name: "data flow", State: Warn, Detail: human,
			Next: "no delivery acked recently - check the auth and network checks above"}
	}
	return Check{Name: "data flow", State: Ok, Detail: human}
}

func readStatus(stateDir string) (status, bool) {
	if stateDir == "" {
		stateDir = "/var/lib/wakora"
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "status.json"))
	if err != nil {
		return status{}, false
	}
	var st status
	if json.Unmarshal(data, &st) != nil {
		return status{}, false
	}
	return st, true
}

func skip(name, why string) Check {
	return Check{Name: name, State: Skip, Detail: why}
}

func hostPort(endpoint string) (string, string) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", "8443"
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" || u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host, port
}

func httpsBase(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	return "https://" + u.Host
}

func subtle(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func humanAgo(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd ago", int(d.Hours())/24)
}

func ringBytes(stateDir string) int64 {
	if stateDir == "" {
		stateDir = "/var/lib/wakora"
	}
	fi, err := os.Stat(filepath.Join(stateDir, "buffer.jsonl"))
	if err != nil {
		return 0
	}
	return fi.Size()
}
