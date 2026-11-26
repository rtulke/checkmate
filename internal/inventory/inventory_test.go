package inventory

import (
	"reflect"
	"strings"
	"testing"
)

const sample = `
defaults:
  user: audit
  become: true
  vars: { ntp: time.example.net, role: none }
groups:
  web:
    port: 2222
    vars: { role: web }
    hosts:
      - web01.example.net
      - name: web02
        address: 10.0.0.12
        user: deploy
        vars: { role: canary }
  eu:
    become: false
    vars: { region: eu, role: eu }
    hosts: [web01.example.net, db01.example.net]
hosts:
  - backup01.example.net
  - name: db01.example.net
    port: 22
`

func TestParse(t *testing.T) {
	inv, err := parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []Host{
		{Name: "web01.example.net", Address: "web01.example.net", User: "audit", Port: 2222, Become: false,
			Groups: []string{"web", "eu"}, Vars: map[string]any{"ntp": "time.example.net", "role": "eu", "region": "eu"}},
		{Name: "web02", Address: "10.0.0.12", User: "deploy", Port: 2222, Become: true,
			Groups: []string{"web"}, Vars: map[string]any{"ntp": "time.example.net", "role": "canary"}},
		{Name: "db01.example.net", Address: "db01.example.net", User: "audit", Port: 22, Become: false,
			Groups: []string{"eu"}, Vars: map[string]any{"ntp": "time.example.net", "role": "eu", "region": "eu"}},
		{Name: "backup01.example.net", Address: "backup01.example.net", User: "audit", Become: true,
			Vars: map[string]any{"ntp": "time.example.net", "role": "none"}},
	}
	if !reflect.DeepEqual(inv.Hosts, want) {
		for i := range inv.Hosts {
			if i < len(want) && !reflect.DeepEqual(inv.Hosts[i], want[i]) {
				t.Errorf("host %d:\n got %+v\nwant %+v", i, inv.Hosts[i], want[i])
			}
		}
		if len(inv.Hosts) != len(want) {
			t.Errorf("%d hosts, want %d", len(inv.Hosts), len(want))
		}
	}
	if got := inv.Hosts[1].Destination(); got != "deploy@10.0.0.12" {
		t.Errorf("destination %q", got)
	}
	if !reflect.DeepEqual(inv.Groups, []string{"web", "eu"}) {
		t.Errorf("groups %v", inv.Groups)
	}
}

func TestLimit(t *testing.T) {
	inv, err := parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	names := func(patterns string) string {
		hosts, err := inv.Limit(patterns)
		if err != nil {
			return "error: " + err.Error()
		}
		var n []string
		for _, h := range hosts {
			n = append(n, h.Name)
		}
		return strings.Join(n, " ")
	}
	for patterns, want := range map[string]string{
		"web":                  "web01.example.net web02",
		"eu,web02":             "web01.example.net web02 db01.example.net",
		"*.example.net":        "web01.example.net db01.example.net backup01.example.net",
		"web0?":                "web02",
		" db01.example.net , ": "db01.example.net",
	} {
		if got := names(patterns); got != want {
			t.Errorf("limit %q: %s, want %s", patterns, got, want)
		}
	}
	if got := names("web,wbe"); !strings.Contains(got, `"wbe" matches no host or group (groups: eu, web)`) {
		t.Errorf("typo: %s", got)
	}
}

func TestParseErrors(t *testing.T) {
	for src, want := range map[string]string{
		``:                                        "empty",
		`groups: {}`:                              "lists no hosts",
		`hosts: [{address: 10.0.0.1}]`:            "has no name",
		`hosts: ["a b"]`:                          "must not contain blanks",
		`hosts: [{name: a, usr: x}]`:              "usr",
		`defauls: {user: x}` + "\nhosts: [a]":     "defauls",
		`groups: {all: {hosts: [a]}}`:             `invalid group name "all"`,
		`groups: {"a,b": {hosts: [a]}}`:           "invalid group name",
		`groups: {web: {host: [a]}}`:              "group web",
		`groups: [web]`:                           "groups must be a mapping",
		`hosts: [{name: a, port: 70000}]`:         "invalid port",
		`hosts: [{name: a, device: "Cisco IOS"}]`: "invalid device",
		`defaults: {become: true}` + "\nhosts: [{name: a, device: ios}]": "become needs a shell",
	} {
		if _, err := parse([]byte(src)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want one mentioning %q", src, err, want)
		}
	}
}

func TestDevices(t *testing.T) {
	inv, err := parse([]byte(`
defaults: { become: true }
groups:
  switches:
    device: ios
    become: false
    hosts: [sw01, { name: fw01, device: fortios }]
hosts: [web01]
`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, h := range inv.Hosts {
		got[h.Name] = h.Device
	}
	want := map[string]string{"sw01": "ios", "fw01": "fortios", "web01": ""}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("devices %v, want %v", got, want)
	}
}
