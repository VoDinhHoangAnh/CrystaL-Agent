package collector

import (
	"errors"
	"testing"
)

func TestClassifyWinErr(t *testing.T) {
	st, reason, _ := ClassifyWinErr(errors.New("Access is denied."))
	if st != "unavailable" || reason != "access_denied" {
		t.Fatalf("got %s %s", st, reason)
	}
	st, reason, _ = ClassifyWinErr(errors.New("The specified channel could not be found. (15007)"))
	if reason != "channel_missing" {
		t.Fatalf("got %s", reason)
	}
	st, reason, _ = ClassifyWinErr(errors.New("No events were found"))
	if st != "available" || reason != "no_events" {
		t.Fatalf("empty channel must not be fatal: %s %s", st, reason)
	}
}
