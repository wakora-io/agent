package pause

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"wakora.io/agent/internal/atomicfile"
)

const (
	Unpaid = "unpaid"
	Plan   = "plan"
)

func Path(stateDir string) string {
	return filepath.Join(stateDir, "paused")
}

func Normalize(reason string) string {
	switch strings.TrimSpace(reason) {
	case "":
		return ""
	case Unpaid:
		return Unpaid
	default:
		return Plan
	}
}

func Read(stateDir string) string {
	b, err := os.ReadFile(Path(stateDir))
	if err != nil {
		return ""
	}
	return Normalize(string(b))
}

func Write(stateDir, reason string) error {
	reason = Normalize(reason)
	if reason == "" {
		if err := os.Remove(Path(stateDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	return atomicfile.Write(Path(stateDir), []byte(reason+"\n"), 0o644)
}

func Message(reason string) string {
	switch Normalize(reason) {
	case Unpaid:
		return "ERROR: this host is not monitored: the workspace has an unpaid invoice. Nothing is collected until it is paid, then monitoring resumes on its own."
	case Plan:
		return "ERROR: this host is not monitored: the workspace plan does not cover it. Nothing is collected until it is chosen in billing or the plan is upgraded, then monitoring resumes on its own."
	}
	return ""
}
