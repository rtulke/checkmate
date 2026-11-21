package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rtulke/checkmate/internal/engine"
)

func TestAttackLayer(t *testing.T) {
	r := &engine.Report{
		Policy: "Test",
		Results: []engine.Result{
			{ID: "A", Status: engine.StatusPass, Tags: []string{"attack", "attack-t1053.003", "attack-persistence"}},
			{ID: "B", Status: engine.StatusFail, Tags: []string{"attack-t1053.003"}},
			{ID: "C", Status: engine.StatusPass, Tags: []string{"attack-T1548.001"}},
			{ID: "D", Status: engine.StatusSkip, Tags: []string{"attack-t1611"}},
			{ID: "E", Status: engine.StatusWaived, Tags: []string{"attack-t1110"}},
		},
	}
	var b bytes.Buffer
	if err := AttackLayer(&b, r, "test"); err != nil {
		t.Fatal(err)
	}
	var layer struct {
		Domain     string `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Color       string `json:"color"`
			Comment     string `json:"comment"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(b.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	if layer.Domain != "enterprise-attack" {
		t.Errorf("domain %q", layer.Domain)
	}
	got := map[string]string{}
	for _, tech := range layer.Techniques {
		got[tech.TechniqueID] = tech.Color
	}
	want := map[string]string{"T1053.003": "#e74c3c", "T1548.001": "#2ecc71", "T1110": "#3498db"}
	if len(got) != len(want) {
		t.Errorf("techniques %v, want %v (skipped checks are left out, tactics are no techniques)", got, want)
	}
	for id, color := range want {
		if got[id] != color {
			t.Errorf("%s: color %s, want %s (the worst result wins)", id, got[id], color)
		}
	}
}
