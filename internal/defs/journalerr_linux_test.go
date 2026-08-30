package defs

import (
	"os/exec"
	"strings"
	"testing"
)

func TestJournalErrCarriesTheCircumstances(t *testing.T) {
	_, err := exec.Command("sh", "-c", "exit 1").Output()
	if err == nil {
		t.Fatal("setup did not fail")
	}
	silent := journalErr(err, nil, 11, true).Error()
	if !strings.Contains(silent, "no output") || !strings.Contains(silent, "idents 11") || !strings.Contains(silent, "cursor") {
		t.Fatalf("a silent failure said nothing useful: %s", silent)
	}
	first := journalErr(err, nil, 3, false).Error()
	if !strings.Contains(first, "first read") {
		t.Fatalf("the first read was not named: %s", first)
	}
	spoken := journalErr(err, []byte("Failed to seek to cursor: Invalid argument\nmore"), 3, true).Error()
	if !strings.Contains(spoken, "Failed to seek to cursor") || strings.Contains(spoken, "more") {
		t.Fatalf("stdout was not taken as the reason: %s", spoken)
	}
}

func TestJournalErrKeepsStderrWhenThereIsSome(t *testing.T) {
	_, err := exec.Command("sh", "-c", "echo 'Failed to open files' >&2; exit 1").Output()
	if err == nil {
		t.Fatal("setup did not fail")
	}
	got := journalErr(err, nil, 2, false).Error()
	if !strings.Contains(got, "Failed to open files") {
		t.Fatalf("stderr was dropped: %s", got)
	}
	if strings.Contains(got, "no output") {
		t.Fatalf("stderr was there and the message still said no output: %s", got)
	}
}
