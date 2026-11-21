package examples

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/policy"
)

var attackTechniqueTag = regexp.MustCompile(`^attack-t\d{4}(\.\d{3})?$`)

// attackTactics are the tactic tags (attack-<shortname>) of ATT&CK Enterprise.
var attackTactics = map[string]bool{
	"reconnaissance": true, "resource-development": true, "initial-access": true, "execution": true,
	"persistence": true, "privilege-escalation": true, "stealth": true, "defense-impairment": true,
	"credential-access": true, "discovery": true, "lateral-movement": true, "collection": true,
	"command-and-control": true, "exfiltration": true, "impact": true,
}

// TestAttackTags checks that every attack-* tag names an existing ATT&CK
// technique (examples/attack/techniques.txt) or tactic, and that a check
// tagged with a technique also carries one of the technique's tactics.
func TestAttackTags(t *testing.T) {
	fh, err := os.Open("attack/techniques.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	tactics := map[string][]string{}
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		tactics["attack-"+strings.ToLower(f[0])] = strings.Split(f[1], ",")
	}
	tagged := 0
	for _, file := range policyFiles(t) {
		p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
		if err != nil {
			continue
		}
		checks, _ := policy.Expand(p, platforms["debian12"], nil)
		for _, c := range checks {
			has := map[string]bool{}
			for _, tag := range c.Tags {
				has[tag] = true
			}
			for _, tag := range c.Tags {
				if !strings.HasPrefix(tag, "attack-") {
					continue
				}
				name := strings.TrimPrefix(tag, "attack-")
				if attackTechniqueTag.MatchString(tag) {
					tagged++
					ts, ok := tactics[tag]
					if !ok {
						t.Errorf("%s %s: %s is not an ATT&CK technique", file, c.ID, tag)
						continue
					}
					match := false
					for _, tactic := range ts {
						match = match || has["attack-"+tactic]
					}
					if !match {
						t.Errorf("%s %s: %s needs one of its tactic tags: attack-%s", file, c.ID, tag, strings.Join(ts, ", attack-"))
					}
				} else if !attackTactics[name] {
					t.Errorf("%s %s: %s is neither a technique nor a tactic", file, c.ID, tag)
				}
			}
		}
	}
	t.Logf("%d technique tags checked", tagged)
}
