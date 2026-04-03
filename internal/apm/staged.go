package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

type StagedChange struct {
	ID         string `json:"id"`
	Service    string `json:"service"`
	Kind       string `json:"kind"`
	StagedPath string `json:"stagedPath"`
	TargetPath string `json:"targetPath"`
	Command    string `json:"command"`
	Impact     string `json:"impact"`
	ContentSha string `json:"contentSha"`
	State      string `json:"state"`
	Note       string `json:"note,omitempty"`
}

func stagedDir(base string) string { return filepath.Join(base, "staged") }

func Stage(base string, c StagedChange, content []byte) (StagedChange, bool, error) {
	dir := stagedDir(base)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return c, false, err
	}
	sum := sha256.Sum256(content)
	c.ContentSha = hex.EncodeToString(sum[:])
	c.StagedPath = filepath.Join(dir, c.ID+".staged")
	c.State = "pending_activation"

	prev, _ := loadStaged(base, c.ID)
	if prev.ContentSha == c.ContentSha && prev.State != "" {
		return prev, false, nil
	}
	if err := os.WriteFile(c.StagedPath, content, 0o644); err != nil {
		return c, false, err
	}
	meta, err := json.Marshal(c)
	if err != nil {
		return c, false, err
	}
	if err := os.WriteFile(filepath.Join(dir, c.ID+".json"), meta, 0o600); err != nil {
		return c, false, err
	}
	return c, true, nil
}

func loadStaged(base, id string) (StagedChange, error) {
	var c StagedChange
	raw, err := os.ReadFile(filepath.Join(stagedDir(base), id+".json"))
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(raw, &c)
	return c, err
}

func MarkActivated(base, id string) error {
	c, err := loadStaged(base, id)
	if err != nil {
		return err
	}
	c.State = "active"
	meta, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stagedDir(base), id+".json"), meta, 0o600)
}

func StagedState(base, id string) string {
	c, err := loadStaged(base, id)
	if err != nil {
		return ""
	}
	return c.State
}

// ResetStaged drops the staged files so the state machine re-arms: the next
// Stage() of the same content is new again and re-raises action_required.
// Used when an active change was deactivated externally (operator removed
// the ini / env drop-in without telling us).
func ResetStaged(base, id string) error {
	dir := stagedDir(base)
	for _, name := range []string{id + ".json", id + ".staged"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
