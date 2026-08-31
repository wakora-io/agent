//go:build linux

package defs

import (
	"errors"
	"os/exec"
	"testing"
)

func exitErrWith(stderr string) error {
	cmd := exec.Command("sh", "-c", "exit 1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return err
	}
	ee.Stderr = []byte(stderr)
	return ee
}

func TestSilentNonZeroMeansNothingMatched(t *testing.T) {
	if !journalNoEntries(exitErrWith(""), nil) {
		t.Fatal("a silent exit status with nothing on either stream means the filter matched no entries")
	}
	if !journalNoEntries(exitErrWith("  \n"), []byte("\n \n")) {
		t.Fatal("whitespace is not output")
	}
}

func TestARealFailureIsNeverReadAsEmpty(t *testing.T) {
	if journalNoEntries(exitErrWith("Failed to open /nonexistent: No such file or directory"), nil) {
		t.Fatal("a reason on stderr is a failure, not an empty result")
	}
	if journalNoEntries(exitErrWith(""), []byte("Failed to determine journal files")) {
		t.Fatal("a reason on stdout is a failure, not an empty result")
	}
	if journalNoEntries(errors.New("exec: \"journalctl\": executable file not found in $PATH"), nil) {
		t.Fatal("a missing binary is a failure, not an empty result")
	}
}
