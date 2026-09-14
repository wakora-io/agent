package redact

import (
	"strings"
	"testing"
)

func TestAttrMasksEveryQueryValueAndKeepsTheNames(t *testing.T) {
	got := Attr("url.full", "https://api.example.com/v1/items?key=PLACEHOLDER_SECRET&page=2")
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("query value leaked: %q", got)
	}
	if got != "https://api.example.com/v1/items?key=***&page=***" {
		t.Fatalf("names or shape lost: %q", got)
	}
}

func TestAttrMasksUnknownParameterNames(t *testing.T) {
	for _, in := range []string{
		"https://api.example.com/x?k=PLACEHOLDER_SECRET",
		"https://api.example.com/x?sv=PLACEHOLDER_SECRET",
		"https://api.example.com/x?whatever_vendor_calls_it=PLACEHOLDER_SECRET",
	} {
		if got := Attr("url.full", in); strings.Contains(got, "PLACEHOLDER_SECRET") {
			t.Fatalf("an unlisted parameter leaked: %q -> %q", in, got)
		}
	}
}

func TestAttrDropsTheFragmentWhole(t *testing.T) {
	got := Attr("url.full", "https://app.example.com/cb#access_token=PLACEHOLDER_SECRET&type=bearer")
	if strings.Contains(got, "PLACEHOLDER_SECRET") || strings.Contains(got, "#") {
		t.Fatalf("fragment survived: %q", got)
	}
	if got != "https://app.example.com/cb" {
		t.Fatalf("path lost: %q", got)
	}
}

func TestAttrMasksUserinfoAndKeepsTheHost(t *testing.T) {
	got := Attr("url.full", "https://svcuser:PLACEHOLDER_SECRET@api.example.com/v1/x")
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("credential leaked: %q", got)
	}
	if got != "https://svcuser:***@api.example.com/v1/x" {
		t.Fatalf("url lost its shape: %q", got)
	}
}

func TestAttrMasksUrlInsideAnySurroundingText(t *testing.T) {
	sql := `INSERT INTO jobs (url) VALUES ('https://api.example.com/v1/x?key=PLACEHOLDER_SECRET')`
	got := Attr("db.query.text", sql)
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("url inside sql leaked: %q", got)
	}
	if !strings.HasPrefix(got, "INSERT INTO jobs (url) VALUES (") {
		t.Fatalf("surrounding text was mangled: %q", got)
	}
	msg := "connect failed for https://api.example.com/hook?token=PLACEHOLDER_SECRET after 3 tries"
	got = Attr("exception.message", msg)
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("url inside a message leaked: %q", got)
	}
	if !strings.HasSuffix(got, " after 3 tries") {
		t.Fatalf("message tail was swallowed: %q", got)
	}
}

func TestAttrLeavesSqlPlaceholdersAndPlainValuesAlone(t *testing.T) {
	for key, in := range map[string]string{
		"db.query.text":        "SELECT id FROM orders WHERE customer = ? AND status = ? LIMIT 20",
		"url.path":             "/v1/items/42",
		"server.address":       "db.internal",
		"code.file.path":       "/var/www/app/src/Handler.php",
		"user_agent.original":  "Mozilla/5.0 (compatible; ExampleBot/1.0; +https://bot.example.com/info)",
		"db.operation.name":    "SELECT",
		"http.request.method":  "POST",
		"process.runtime.name": "php",
	} {
		if got := Attr(key, in); got != in {
			t.Fatalf("%s was altered: %q -> %q", key, in, got)
		}
	}
}

func TestAttrMasksSensitiveHeadersOnly(t *testing.T) {
	if got := Attr("http.request.header.authorization", "Bearer PLACEHOLDER_SECRET"); got != mask {
		t.Fatalf("authorization header leaked: %q", got)
	}
	if got := Attr("http.request.header.cookie", "sid=PLACEHOLDER_SECRET"); got != mask {
		t.Fatalf("cookie header leaked: %q", got)
	}
	if got := Attr("http.request.header.x_api_key", "PLACEHOLDER_SECRET"); got != mask {
		t.Fatalf("api key header leaked: %q", got)
	}
	if got := Attr("http.response.header.content_length", "1751"); got != "1751" {
		t.Fatalf("an ordinary header was masked: %q", got)
	}
}

func TestAttrMasksTheStandaloneQueryAttribute(t *testing.T) {
	got := Attr("url.query", "key=PLACEHOLDER_SECRET&page=2")
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("standalone query leaked: %q", got)
	}
	if got != "key=***&page=***" {
		t.Fatalf("names lost: %q", got)
	}
}

func TestAttrMasksTargetStyleValues(t *testing.T) {
	got := Attr("http.target", "/v1/items?key=PLACEHOLDER_SECRET")
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("target query leaked: %q", got)
	}
	if got != "/v1/items?key=***" {
		t.Fatalf("target shape lost: %q", got)
	}
}

func TestScrubMasksQuerySecretsInLogLinesAndKeepsTheRest(t *testing.T) {
	line := `198.51.100.7 - - [14/Sep/2026:12:00:01 +0000] "GET /v1/items?key=PLACEHOLDER_SECRET&page=2 HTTP/1.1" 200 512`
	got := Scrub(line)
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("access log query secret leaked: %q", got)
	}
	for _, keep := range []string{"page=2", "HTTP/1.1", "200 512", "198.51.100.7"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("log line lost %q: %q", keep, got)
		}
	}
}

func TestScrubCoversUnlistedShortNamesOnlyWhenTheValueIsLong(t *testing.T) {
	short := Scrub(`GET /catalog?code=LV&v=2 HTTP/1.1`)
	if short != `GET /catalog?code=LV&v=2 HTTP/1.1` {
		t.Fatalf("a short ordinary value was masked: %q", short)
	}
	long := Scrub(`GET /cb?code=PLACEHOLDER_SECRET_LONG_VALUE HTTP/1.1`)
	if strings.Contains(long, "PLACEHOLDER_SECRET_LONG_VALUE") {
		t.Fatalf("a long oauth code leaked: %q", long)
	}
}

func TestScrubStopsAtTheParameterBoundary(t *testing.T) {
	got := Scrub(`/x?token=PLACEHOLDER_SECRET&page=7&sort=name`)
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("token leaked: %q", got)
	}
	if got != `/x?token=***&page=7&sort=name` {
		t.Fatalf("redaction swallowed the neighbouring parameters: %q", got)
	}
}

func TestAttrKeepsValuelessAndEmptyParameters(t *testing.T) {
	got := Attr("url.full", "https://api.example.com/x?debug&trace=&key=PLACEHOLDER_SECRET")
	if strings.Contains(got, "PLACEHOLDER_SECRET") {
		t.Fatalf("value leaked: %q", got)
	}
	if got != "https://api.example.com/x?debug&trace=&key=***" {
		t.Fatalf("valueless parameters lost: %q", got)
	}
}
