package tracking

import "testing"

func TestShouldTrack(t *testing.T) {
	if !ShouldTrack("high", false) || !ShouldTrack("critical", false) {
		t.Fatal("high/critical must track")
	}
	if !ShouldTrack("medium", true) || ShouldTrack("medium", false) {
		t.Fatal("medium follows policy")
	}
	if ShouldTrack("low", true) || ShouldTrack("info", true) {
		t.Fatal("low/info stay out of current tracking")
	}
}
