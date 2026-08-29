package apm

import "testing"

func TestStagedIDsThatEscapeTheDirAreRefused(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"../../etc/cron.d/x", "..", "a/b", "a\\b", "", "ok/../bad", "a..b/../.."} {
		if _, _, err := Stage(dir, StagedChange{ID: id, Service: "s"}, []byte("x")); err == nil {
			t.Fatalf("staged id %q was accepted", id)
		}
	}
	if err := MarkActivated(dir, "../x"); err == nil {
		t.Fatal("MarkActivated accepted a traversal id")
	}
	if err := ResetStaged(dir, "../x"); err == nil {
		t.Fatal("ResetStaged accepted a traversal id")
	}
	if s := StagedState(dir, "../x"); s != "" {
		t.Fatalf("StagedState answered %q for a traversal id", s)
	}
	for _, id := range []string{"apmphp-apm-php-8.3", "apmnode-node-myapp@prod", "apmdotnet-apm-dotnet-iis", "apmphp-web-8.1-deep-cleanup"} {
		if _, _, err := Stage(dir, StagedChange{ID: id, Service: "s"}, []byte("x")); err != nil {
			t.Fatalf("real stage id %q was refused: %v", id, err)
		}
	}
}

func TestStagedLifecycle(t *testing.T) {
	dir := t.TempDir()
	c := StagedChange{ID: "apmphp-web", Service: "web", Kind: "otel-spans", TargetPath: "/etc/php/conf.d/x.ini", Impact: "reload"}

	staged, isNew, err := Stage(dir, c, []byte("zend_extension=x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("first stage must be new")
	}
	if staged.State != "pending_activation" {
		t.Fatalf("state: %q", staged.State)
	}
	if StagedState(dir, "apmphp-web") != "pending_activation" {
		t.Fatal("persisted state mismatch")
	}

	_, isNew2, err := Stage(dir, c, []byte("zend_extension=x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if isNew2 {
		t.Fatal("re-staging identical content must NOT be new (no duplicate action_required)")
	}

	if err := MarkActivated(dir, "apmphp-web"); err != nil {
		t.Fatal(err)
	}
	if StagedState(dir, "apmphp-web") != "active" {
		t.Fatal("should be active after MarkActivated")
	}
}

func TestStagedContentChangeReStages(t *testing.T) {
	dir := t.TempDir()
	c := StagedChange{ID: "apmphp-web", Service: "web"}
	if _, isNew, _ := Stage(dir, c, []byte("v1")); !isNew {
		t.Fatal("v1 new")
	}
	_, isNew, _ := Stage(dir, c, []byte("v2"))
	if !isNew {
		t.Fatal("changed content must re-stage as new")
	}
}

func TestStageCommandShapeChangeReissues(t *testing.T) {
	dir := t.TempDir()
	c := StagedChange{ID: "apmphp-web", Service: "web", Command: "cp S T && reload"}
	if _, isNew, _ := Stage(dir, c, []byte("ini")); !isNew {
		t.Fatal("v1 new")
	}
	c.Command = "backup && cp S T && test && reload"
	staged, isNew, err := Stage(dir, c, []byte("ini"))
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("same content with a NEW command shape must reissue (stale instructions rendered in the console for days)")
	}
	if staged.Command != c.Command {
		t.Fatalf("command: %q", staged.Command)
	}
	if got, _ := loadStaged(dir, "apmphp-web"); got.Command != c.Command {
		t.Fatalf("persisted command: %q", got.Command)
	}

	if _, isNew, _ = Stage(dir, c, []byte("ini")); isNew {
		t.Fatal("unchanged command must stay deduped")
	}

	if err := MarkActivated(dir, "apmphp-web"); err != nil {
		t.Fatal(err)
	}
	c.Command = "yet another shape"
	staged, isNew, _ = Stage(dir, c, []byte("ini"))
	if isNew {
		t.Fatal("an ACTIVE change must never reissue action_required on a command refresh")
	}
	if staged.State != "active" {
		t.Fatalf("state must survive the metadata refresh, got %q", staged.State)
	}
}

func TestResetStagedReArms(t *testing.T) {
	dir := t.TempDir()
	c := StagedChange{ID: "apmphp-web", Service: "web"}
	if _, isNew, _ := Stage(dir, c, []byte("v1")); !isNew {
		t.Fatal("v1 new")
	}
	if err := MarkActivated(dir, "apmphp-web"); err != nil {
		t.Fatal(err)
	}
	if err := ResetStaged(dir, "apmphp-web"); err != nil {
		t.Fatal(err)
	}
	if StagedState(dir, "apmphp-web") != "" {
		t.Fatal("state must be empty after reset")
	}
	_, isNew, err := Stage(dir, c, []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("same content after reset must be new again (fresh action_required)")
	}
	if err := ResetStaged(dir, "missing"); err != nil {
		t.Fatal("resetting a missing id must be a no-op, got", err)
	}
}
