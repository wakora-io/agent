package defs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

const (
	k8sNamespaceCap = 50
	k8sTopPodsCap   = 20
)

var k8sKubeconfigCandidates = []string{
	"/etc/rancher/k3s/k3s.yaml",
	"/etc/kubernetes/admin.conf",
	"/var/lib/k0s/pki/admin.conf",
}

const k8sServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type kubeClient struct {
	base   string
	token  string
	client *http.Client
}

func runK8s(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	kc, source, err := connectKube(p.Path, timeout)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	o.Check.Target = source

	version := kc.version()
	nodes, nodesReady, kubelet, err := kc.nodes()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "nodes: " + err.Error()
		return
	}
	pods, err := kc.pods()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "pods: " + err.Error()
		return
	}
	usage := kc.podMetrics()

	o.Check.Status = "ok"
	prefix := "svc." + service + "."
	phases := map[string]int{}
	nsPods := map[string]int{}
	restarts := 0
	crashloop := 0
	for _, pod := range pods {
		phases[pod.phase]++
		nsPods[pod.namespace]++
		restarts += pod.restarts
		if pod.crashloop {
			crashloop++
		}
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "nodes", Value: float64(nodes)},
		protocol.MetricPoint{Name: prefix + "nodes_ready", Value: float64(nodesReady)},
		protocol.MetricPoint{Name: prefix + "pods", Value: float64(len(pods))},
		protocol.MetricPoint{Name: prefix + "pods_running", Value: float64(phases["Running"])},
		protocol.MetricPoint{Name: prefix + "pods_pending", Value: float64(phases["Pending"])},
		protocol.MetricPoint{Name: prefix + "pods_failed", Value: float64(phases["Failed"])},
		protocol.MetricPoint{Name: prefix + "pods_crashloop", Value: float64(crashloop)},
		protocol.MetricPoint{Name: prefix + "restarts_total", Value: float64(restarts)},
		protocol.MetricPoint{Name: prefix + "namespaces", Value: float64(len(nsPods))},
	)

	type nsUse struct {
		cpu float64
		mem float64
	}
	nsUsage := map[string]*nsUse{}
	for _, u := range usage {
		if nsUsage[u.namespace] == nil {
			nsUsage[u.namespace] = &nsUse{}
		}
		nsUsage[u.namespace].cpu += u.cpuMilli
		nsUsage[u.namespace].mem += u.memBytes
	}
	names := sortedKeysByCount(nsPods)
	if len(names) > k8sNamespaceCap {
		names = names[:k8sNamespaceCap]
	}
	for _, ns := range names {
		tags := map[string]string{"namespace": ns}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "ns.pods", Value: float64(nsPods[ns]), Tags: tags})
		if u := nsUsage[ns]; u != nil {
			o.Metrics = append(o.Metrics,
				protocol.MetricPoint{Name: prefix + "ns.cpu_millicores", Value: round1(u.cpu), Tags: tags},
				protocol.MetricPoint{Name: prefix + "ns.mem_bytes", Value: u.mem, Tags: tags},
			)
		}
		payload, _ := json.Marshal(map[string]int{"pods": nsPods[ns]})
		o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "namespace", Key: ns, Payload: string(payload)})
	}

	sort.Slice(usage, func(i, j int) bool { return usage[i].cpuMilli > usage[j].cpuMilli })
	if len(usage) > k8sTopPodsCap {
		usage = usage[:k8sTopPodsCap]
	}
	for _, u := range usage {
		tags := map[string]string{"namespace": u.namespace, "pod": u.pod}
		o.Metrics = append(o.Metrics,
			protocol.MetricPoint{Name: prefix + "pod.cpu_millicores", Value: round1(u.cpuMilli), Tags: tags},
			protocol.MetricPoint{Name: prefix + "pod.mem_bytes", Value: u.memBytes, Tags: tags},
		)
	}

	o.Facts = map[string]string{}
	if version != "" {
		o.Facts["version"] = version
	}
	if kubelet != "" {
		o.Facts["kubelet"] = kubelet
	}
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

func sortedKeysByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func connectKube(explicitPath string, timeout time.Duration) (*kubeClient, string, error) {
	if kc, err := inClusterKubeClient(timeout); err == nil {
		return kc, "in-cluster serviceaccount", nil
	}
	path := explicitPath
	if path == "" {
		for _, c := range k8sKubeconfigCandidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}
	if path == "" {
		return nil, "", fmt.Errorf("no in-cluster token and no kubeconfig found (set probe path)")
	}
	kc, err := newKubeClient(path, timeout)
	if err != nil {
		return nil, "", err
	}
	return kc, path, nil
}

func inClusterKubeClient(timeout time.Duration) (*kubeClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not in cluster")
	}
	token, err := os.ReadFile(k8sServiceAccountDir + "/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(k8sServiceAccountDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("serviceaccount ca.crt unparseable")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	cfg := &tls.Config{RootCAs: pool}
	return &kubeClient{
		base:   "https://" + net.JoinHostPort(host, port),
		token:  strings.TrimSpace(string(token)),
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg}},
	}, nil
}

func newKubeClient(kubeconfig string, timeout time.Duration) (*kubeClient, error) {
	raw, err := os.ReadFile(kubeconfig)
	if err != nil {
		return nil, err
	}
	server, ca, cert, key := parseKubeconfig(string(raw))
	if server == "" {
		return nil, fmt.Errorf("kubeconfig %s: no server", kubeconfig)
	}
	if cert == nil || key == nil {
		return nil, fmt.Errorf("kubeconfig %s: no inline client cert (token auth not supported)", kubeconfig)
	}
	if ca == nil {
		return nil, fmt.Errorf("kubeconfig %s: no certificate-authority-data (refusing to skip server verification)", kubeconfig)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("kubeconfig %s: certificate-authority-data unparseable", kubeconfig)
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool}
	return &kubeClient{
		base:   strings.TrimRight(server, "/"),
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg}},
	}, nil
}

func parseKubeconfig(raw string) (server string, ca, cert, key []byte) {
	field := func(line, name string) (string, bool) {
		trimmed := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(trimmed, name+":"); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), true
		}
		return "", false
	}
	b64 := func(v string) []byte {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil
		}
		return b
	}
	for _, line := range strings.Split(raw, "\n") {
		if v, ok := field(line, "server"); ok && server == "" {
			server = v
		}
		if v, ok := field(line, "certificate-authority-data"); ok && ca == nil {
			ca = b64(v)
		}
		if v, ok := field(line, "client-certificate-data"); ok && cert == nil {
			cert = b64(v)
		}
		if v, ok := field(line, "client-key-data"); ok && key == nil {
			key = b64(v)
		}
	}
	return server, ca, cert, key
}

func (kc *kubeClient) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, kc.base+path, nil)
	if err != nil {
		return err
	}
	if kc.token != "" {
		req.Header.Set("Authorization", "Bearer "+kc.token)
	}
	resp, err := kc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.Unmarshal(body, out)
}

func (kc *kubeClient) getRaw(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, kc.base+path, nil)
	if err != nil {
		return nil, err
	}
	if kc.token != "" {
		req.Header.Set("Authorization", "Bearer "+kc.token)
	}
	resp, err := kc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return body, nil
}

func (kc *kubeClient) version() string {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if kc.get("/version", &v) != nil {
		return ""
	}
	return v.GitVersion
}

func (kc *kubeClient) nodes() (total, ready int, kubelet string, err error) {
	var list struct {
		Items []struct {
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
				NodeInfo struct {
					KubeletVersion string `json:"kubeletVersion"`
				} `json:"nodeInfo"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := kc.get("/api/v1/nodes", &list); err != nil {
		return 0, 0, "", err
	}
	for _, n := range list.Items {
		total++
		if kubelet == "" {
			kubelet = n.Status.NodeInfo.KubeletVersion
		}
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				ready++
			}
		}
	}
	return total, ready, kubelet, nil
}

type k8sPod struct {
	namespace string
	name      string
	phase     string
	restarts  int
	crashloop bool
}

func (kc *kubeClient) pods() ([]k8sPod, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					RestartCount int `json:"restartCount"`
					State        struct {
						Waiting struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := kc.get("/api/v1/pods?limit=5000", &list); err != nil {
		return nil, err
	}
	pods := make([]k8sPod, 0, len(list.Items))
	for _, it := range list.Items {
		pod := k8sPod{namespace: it.Metadata.Namespace, phase: it.Status.Phase}
		for _, cs := range it.Status.ContainerStatuses {
			pod.restarts += cs.RestartCount
			if cs.State.Waiting.Reason == "CrashLoopBackOff" {
				pod.crashloop = true
			}
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

type k8sPodUsage struct {
	namespace string
	pod       string
	cpuMilli  float64
	memBytes  float64
}

func (kc *kubeClient) podMetrics() []k8sPodUsage {
	var list struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Containers []struct {
				Usage struct {
					CPU    string `json:"cpu"`
					Memory string `json:"memory"`
				} `json:"usage"`
			} `json:"containers"`
		} `json:"items"`
	}
	if kc.get("/apis/metrics.k8s.io/v1beta1/pods", &list) != nil {
		return nil
	}
	out := make([]k8sPodUsage, 0, len(list.Items))
	for _, it := range list.Items {
		u := k8sPodUsage{namespace: it.Metadata.Namespace, pod: it.Metadata.Name}
		for _, c := range it.Containers {
			u.cpuMilli += parseCPUMilli(c.Usage.CPU)
			u.memBytes += parseMemBytes(c.Usage.Memory)
		}
		out = append(out, u)
	}
	return out
}

func parseCPUMilli(q string) float64 {
	if q == "" {
		return 0
	}
	switch {
	case strings.HasSuffix(q, "n"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(q, "n"), 64)
		return v / 1e6
	case strings.HasSuffix(q, "u"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(q, "u"), 64)
		return v / 1e3
	case strings.HasSuffix(q, "m"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(q, "m"), 64)
		return v
	default:
		v, _ := strconv.ParseFloat(q, 64)
		return v * 1000
	}
}

func parseMemBytes(q string) float64 {
	if q == "" {
		return 0
	}
	units := []struct {
		suffix string
		mult   float64
	}{
		{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40},
		{"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12},
	}
	for _, u := range units {
		if strings.HasSuffix(q, u.suffix) {
			v, _ := strconv.ParseFloat(strings.TrimSuffix(q, u.suffix), 64)
			return v * u.mult
		}
	}
	v, _ := strconv.ParseFloat(q, 64)
	return v
}
