package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type request struct {
	TeamKey   string `json:"teamKey"`
	MachineID string `json:"machineId"`
	Hostname  string `json:"hostname"`
}

type response struct {
	ServerID string `json:"serverId"`
	Key      string `json:"key"`
}

func Register(client *http.Client, url, teamKey, machineID, hostname string) (string, string, error) {
	body, err := json.Marshal(request{TeamKey: teamKey, MachineID: machineID, Hostname: hostname})
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", "", fmt.Errorf("register: %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	var r response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", err
	}
	if r.ServerID == "" || r.Key == "" {
		return "", "", fmt.Errorf("register: incomplete response")
	}
	return r.ServerID, r.Key, nil
}
