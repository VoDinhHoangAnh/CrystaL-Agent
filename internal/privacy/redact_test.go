package privacy

import "testing"

func TestRedactDoesNotKeepValue(t *testing.T) {
	r := RedactCommandLine(`app.exe --api-key=SUPERSECRET extra`)
	if !r.Indicator {
		t.Fatal("expected indicator")
	}
	if r.Redacted == "" || contains(r.Redacted, "SUPERSECRET") {
		t.Fatalf("secret leaked in redacted text: %q", r.Redacted)
	}
	if r.MatchedValue != "" {
		t.Fatal("matched value must not be retained")
	}
	if r.PatternType == "" || r.Field != "command_line" {
		t.Fatalf("missing metadata: %+v", r)
	}
}

func TestRedactBenign(t *testing.T) {
	r := RedactCommandLine(`notepad.exe file.txt`)
	if r.Indicator || r.Redacted != `notepad.exe file.txt` {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestAssertNoSecret(t *testing.T) {
	orig := `pwsh -Command password=hunter2`
	if !AssertNoSecret("finding: credential-like parameter", orig) {
		t.Fatal("false positive")
	}
	if AssertNoSecret("hunter2 stored here", orig) {
		t.Fatal("should detect leak")
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && (len(s) >= len(sub)) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
