package defs

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestExecErrTextCarriesTheReasonNotJustTheCode(t *testing.T) {
	_, err := exec.Command("sh", "-c", "echo 'No journal files were found' >&2; exit 1").Output()
	if err == nil {
		t.Fatal("setup did not fail")
	}
	got := execErrText(err).Error()
	if !strings.Contains(got, "No journal files were found") {
		t.Fatalf("the reason was dropped: %s", got)
	}
	if !strings.Contains(got, "exit status 1") {
		t.Fatalf("the exit code was dropped: %s", got)
	}
}

func TestExecErrTextKeepsASilentFailureAsItIs(t *testing.T) {
	_, err := exec.Command("sh", "-c", "exit 3").Output()
	if err == nil {
		t.Fatal("setup did not fail")
	}
	if got := execErrText(err).Error(); got != "exit status 3" {
		t.Fatalf("got %s", got)
	}
}

func TestExecErrTextPassesThroughNonExitErrors(t *testing.T) {
	if execErrText(nil) != nil {
		t.Fatal("nil grew an error")
	}
	plain := errors.New("context deadline exceeded")
	if execErrText(plain).Error() != plain.Error() {
		t.Fatal("a plain error was rewritten")
	}
}

func TestExecErrTextTakesTheFirstMeaningfulLine(t *testing.T) {
	_, err := exec.Command("sh", "-c", "printf '\\n\\n  mkstemp: Read-only file system\\nsecond line\\n' >&2; exit 2").Output()
	if err == nil {
		t.Fatal("setup did not fail")
	}
	got := execErrText(err).Error()
	if !strings.Contains(got, "Read-only file system") {
		t.Fatalf("blank lines swallowed the reason: %s", got)
	}
	if strings.Contains(got, "second line") {
		t.Fatalf("the whole stderr rode along: %s", got)
	}
}
