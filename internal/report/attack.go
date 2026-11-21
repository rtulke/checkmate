package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/rtulke/checkmate/internal/engine"
)

// attackTag matches tags that name an ATT&CK technique, e.g. attack-t1053.003.
var attackTag = regexp.MustCompile(`^attack-(t\d{4}(\.\d{3})?)$`)

// Colors of the ATT&CK Navigator layer, by the worst result of a technique.
var attackColors = []struct {
	status engine.Status
	label  string
	color  string
	score  int
}{
	{engine.StatusError, "error: could not be evaluated", "#8e44ad", 0},
	{engine.StatusFail, "failed: finding or missing mitigation", "#e74c3c", 1},
	{engine.StatusWarn, "warning: finding below the threshold", "#f1c40f", 2},
	{engine.StatusWaived, "waived: accepted deviation", "#3498db", 3},
	{engine.StatusPass, "passed", "#2ecc71", 4},
}

type attackTechnique struct {
	TechniqueID       string `json:"techniqueID"`
	Score             int    `json:"score"`
	Color             string `json:"color"`
	Comment           string `json:"comment"`
	Enabled           bool   `json:"enabled"`
	ShowSubtechniques bool   `json:"showSubtechniques"`
	Metadata          []meta `json:"metadata,omitempty"`
}

type meta struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AttackLayer writes an ATT&CK Navigator layer (format 4.5) that colors every
// technique named by an attack-t* tag with the worst result of its checks.
// Techniques whose checks were all skipped or not applicable are left out.
func AttackLayer(w io.Writer, r *engine.Report, version string) error {
	type agg struct {
		worst  int
		counts map[engine.Status]int
		ids    []string
	}
	rank := map[engine.Status]int{}
	for i, c := range attackColors {
		rank[c.status] = i
	}
	techniques := map[string]*agg{}
	for _, res := range r.Results {
		i, evaluated := rank[res.Status]
		if !evaluated {
			continue
		}
		for _, tag := range res.Tags {
			m := attackTag.FindStringSubmatch(strings.ToLower(tag))
			if m == nil {
				continue
			}
			id := strings.ToUpper(m[1])
			a := techniques[id]
			if a == nil {
				a = &agg{worst: len(attackColors), counts: map[engine.Status]int{}}
				techniques[id] = a
			}
			if i < a.worst {
				a.worst = i
			}
			a.counts[res.Status]++
			if res.Status != engine.StatusPass {
				a.ids = append(a.ids, fmt.Sprintf("%s %s", res.Status, res.ID))
			}
		}
	}

	ids := make([]string, 0, len(techniques))
	for id := range techniques {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var list []attackTechnique
	for _, id := range ids {
		a := techniques[id]
		c := attackColors[a.worst]
		var parts []string
		for _, ac := range attackColors {
			if n := a.counts[ac.status]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(string(ac.status))))
			}
		}
		comment := strings.Join(parts, ", ")
		if len(a.ids) > 0 {
			comment += ": " + strings.Join(a.ids, "; ")
		}
		list = append(list, attackTechnique{
			TechniqueID: id, Score: c.score, Color: c.color, Comment: comment,
			Enabled: true, ShowSubtechniques: true,
			Metadata: []meta{{Name: "checkmate", Value: c.label}},
		})
	}

	var legend []map[string]string
	for _, c := range attackColors {
		legend = append(legend, map[string]string{"label": c.label, "color": c.color})
	}
	layer := map[string]any{
		"name":        "checkmate: " + r.Policy,
		"description": fmt.Sprintf("Results of %s on %s (checkmate %s). Each technique shows the worst result of its checks.", r.Policy, r.Facts.Hostname, version),
		"domain":      "enterprise-attack",
		"versions":    map[string]string{"attack": "20", "navigator": "5.1.0", "layer": "4.5"},
		"techniques":  list,
		"legendItems": legend,
		"gradient": map[string]any{
			"colors":   []string{"#e74c3c", "#f1c40f", "#2ecc71"},
			"minValue": 0, "maxValue": 4,
		},
		"hideDisabled":                  false,
		"selectTechniquesAcrossTactics": true,
		"selectSubtechniquesWithParent": false,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(layer)
}
