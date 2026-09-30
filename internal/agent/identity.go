package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/protocol"
)

const copyReasonMax = 300

func newInstanceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func (a *Agent) Instance() string { return a.instance }

func (a *Agent) restartNow() {
	if a.restart == nil {
		log.Print("identity changed - restart the agent to use it")
		return
	}
	a.restart()
}

func (a *Agent) reidentify(payload string) {
	var r protocol.Reidentity
	if json.Unmarshal([]byte(payload), &r) != nil || r.ServerID == "" || r.Key == "" {
		log.Print("reidentify order ignored: malformed payload")
		return
	}
	prev := a.cfg.ServerID
	if r.ServerID == prev {
		return
	}
	if err := config.MarkIdentityChanged(a.cfg.Dir(), prev); err != nil {
		log.Printf("reidentify failed: %v", err)
		return
	}
	if err := config.SaveIdentity(a.cfg.Dir(), r.ServerID, r.Key); err != nil {
		config.TakeIdentityChanged(a.cfg.Dir())
		log.Printf("reidentify failed: %v", err)
		return
	}
	log.Printf("this host is a copy of server %s - the platform registered it as server %s, restarting with the new identity", prev, r.ServerID)
	a.restartNow()
}

func copyReason(reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	if rs := []rune(reason); len(rs) > copyReasonMax {
		reason = string(rs[:copyReasonMax])
	}
	if reason == "" {
		reason = "the platform could not register this copy as a new host"
	}
	return reason
}

func (a *Agent) refuseCopy(reason string) {
	reason = copyReason(reason)
	of := a.cfg.ServerID
	if err := config.SaveCopyRefusal(a.cfg.Dir(), config.CopyRefusal{Of: of, Reason: reason, At: time.Now().Unix()}); err != nil {
		log.Printf("copy refusal could not be recorded: %v", err)
		return
	}
	moved, err := config.SetAsideCopiedIdentity(a.cfg.Dir())
	if err != nil {
		config.ClearCopyRefusal(a.cfg.Dir())
		log.Printf("copy refusal could not set the identity aside: %v", err)
		return
	}
	log.Printf("this host is a copy of server %s and was not registered as a new host: %s - identity moved to %s, register with: wakora --key <TEAMKEY>", of, reason, moved)
	a.restartNow()
}
