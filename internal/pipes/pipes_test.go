package pipes

import (
	"os/exec"
	"runtime"
	"testing"
)

func TestDrain(t *testing.T) {
	for in, want := range map[string]string{
		`dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q 'install ok installed'`:                     `dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep 'install ok installed' >/dev/null`,
		`lsmod | awk '{print $1}' | grep -qx "$l_mod" && { echo "FAIL - $l_mod is loaded"; l_fail="yes"; }`: `lsmod | awk '{print $1}' | grep -x "$l_mod" >/dev/null && { echo "FAIL - $l_mod is loaded"; l_fail="yes"; }`,
		`if echo "$cpuType" | grep -q "Apple"; then`:                                                        `if echo "$cpuType" | grep "Apple" >/dev/null; then`,
		`printf "%s\n" "$valid" | grep -qxF -- "$s" && continue`:                                            `printf "%s\n" "$valid" | grep -xF -- "$s" >/dev/null && continue`,
		`ufw status | grep -q 'Status: active' && active=$((active+1))`:                                     `ufw status | grep 'Status: active' >/dev/null && active=$((active+1))`,
		`sh -c '! dnf repolist 2>/dev/null | grep -qi epel'`:                                                `sh -c '! dnf repolist 2>/dev/null | grep -i epel >/dev/null'`,
		`xargs -I{} sh -c 'x {} | grep -q "Linger=yes" && echo {} || true' 2>/dev/null`:                     `xargs -I{} sh -c 'x {} | grep "Linger=yes" >/dev/null && echo {} || true' 2>/dev/null`,
		`a | grep -q x 2>&1 || b | grep -Eq -- "(p|d)=${p}/?([[:space:]]|$)" || echo M`:                     `a | grep x 2>&1 >/dev/null || b | grep -E -- "(p|d)=${p}/?([[:space:]]|$)" >/dev/null || echo M`,
		`x=$(a | grep -q b; echo $?)`:                                                                       `x=$(a | grep b >/dev/null; echo $?)`,
		"a | grep -q b\necho next":                                                                          "a | grep b >/dev/null\necho next",
		`a | grep -q 'it;s | "x" & y'`:                                                                      `a | grep 'it;s | "x" & y' >/dev/null`,
		`a | grep -q "say \"hi\"; ok" ; b`:                                                                  `a | grep "say \"hi\"; ok" >/dev/null ; b`,
		`a | grep -q x |& cat`:                                                                              `a | grep x >/dev/null |& cat`,
		`ps | head -1`:                                                                                      `ps | sed -n 1p`,
		`ps | head -n 1 | cut -c1`:                                                                          `ps | sed -n 1p | cut -c1`,
		`ps |head -n3; x`:                                                                                   `ps |sed -n 1,3p; x`,
		"x=`ps | head -1`":                                                                                  "x=`ps | sed -n 1p`",
		"x=`ps | grep -q a`":                                                                                "x=`ps | grep a >/dev/null`",
		// Left alone: not at the end of a pipe, or not quiet.
		`grep -q x /etc/hosts`:            `grep -q x /etc/hosts`,
		`a || grep -q x /etc/hosts`:       `a || grep -q x /etc/hosts`,
		`a | grep -c x`:                   `a | grep -c x`,
		`a | grep -- -q`:                  `a | grep -- -q`,
		`head -1 /etc/hosts`:              `head -1 /etc/hosts`,
		`a | head -c 10`:                  `a | head -c 10`,
		`Get-Content x | Select -First 1`: `Get-Content x | Select -First 1`,
	} {
		if got := Drain(in); got != want {
			t.Errorf("Drain(%q)\n got %q\nwant %q", in, got, want)
		}
		if again := Drain(Drain(in)); again != Drain(in) {
			t.Errorf("Drain is not stable for %q: %q", in, again)
		}
	}
}

// The rewritten pipelines must behave like the original ones, and must not
// fail under pipefail when the producer writes more than a pipe holds.
func TestDrainedPipelinesKeepTheirMeaning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs bash")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	many := `i=0; while [ $i -lt 20000 ]; do echo "line $i padding padding padding padding"; i=$((i+1)); done`
	for script, want := range map[string]string{
		`if { ` + many + `; } | grep -q 'line 3 '; then echo found; else echo missing; fi`: "found\n",
		`if { ` + many + `; } | grep -q 'no such'; then echo found; else echo missing; fi`: "missing\n",
		`{ ` + many + `; } | head -1`:                                                       "line 0 padding padding padding padding\n",
		`{ ` + many + `; } | head -n 2 | wc -l | tr -d ' '`:                                 "2\n",
		`{ ` + many + `; } | grep -qx 'line 7 padding padding padding padding' && echo yes`: "yes\n",
	} {
		out, err := exec.Command(bash, "-o", "pipefail", "-c", Drain(script)).Output()
		if err != nil || string(out) != want {
			t.Errorf("%s\n-> %s\n got %q, %v; want %q", script, Drain(script), out, err, want)
		}
	}
}
