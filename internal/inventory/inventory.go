// Package inventory reads the list of hosts a policy is run against.
//
//	defaults:                 # for every host, optional
//	  user: audit
//	  become: true
//	  vars: { ntp_server: time.example.net }
//
//	groups:
//	  web:
//	    vars: { role: web }
//	    hosts:
//	      - web01.example.net
//	      - name: web02           # a host with its own settings
//	        address: 10.0.0.12
//	        port: 2222
//	        vars: { role: web-canary }
//	  db:
//	    become: false
//	    hosts: [db01.example.net]
//
//	hosts:                    # hosts outside of any group
//	  - backup01.example.net
//
// Settings and variables go from general to specific: defaults, then the
// groups of a host in file order, then the host itself.
package inventory

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Host is one host with everything that applies to it resolved.
type Host struct {
	Name    string         // name in the inventory, used in reports
	Address string         // where to connect; the name if not given
	User    string         // remote user, empty leaves it to ssh
	Port    int            // 0 leaves it to ssh
	Become  bool           // run commands through sudo -n
	Groups  []string       // groups the host belongs to, in file order
	Vars    map[string]any // variables for the policy
}

// Destination is the ssh destination of the host.
func (h Host) Destination() string {
	if h.User != "" {
		return h.User + "@" + h.Address
	}
	return h.Address
}

// Inventory is the list of hosts in file order.
type Inventory struct {
	Path   string
	Hosts  []Host
	Groups []string
}

type settings struct {
	User   *string        `yaml:"user"`
	Port   *int           `yaml:"port"`
	Become *bool          `yaml:"become"`
	Vars   map[string]any `yaml:"vars"`
}

type hostEntry struct {
	Name     string `yaml:"name"`
	Address  string `yaml:"address"`
	settings `yaml:",inline"`
}

// UnmarshalYAML accepts a plain host name or a mapping.
func (h *hostEntry) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		h.Name = node.Value
		return nil
	}
	type plain hostEntry
	return decodeStrict(node, (*plain)(h))
}

type groupEntry struct {
	settings `yaml:",inline"`
	Hosts    []hostEntry `yaml:"hosts"`
}

type file struct {
	Defaults settings    `yaml:"defaults"`
	Groups   yaml.Node   `yaml:"groups"`
	Hosts    []hostEntry `yaml:"hosts"`
}

// Load reads an inventory file.
func Load(filename string) (*Inventory, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	inv, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	inv.Path = filename
	return inv, nil
}

func parse(data []byte) (*Inventory, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("the inventory is empty")
	}
	var f file
	if err := decodeStrict(doc.Content[0], &f); err != nil {
		return nil, err
	}

	inv := &Inventory{}
	index := map[string]int{}
	// add merges an entry into the host of that name, creating it first
	// with the defaults.
	add := func(e hostEntry, group string, groupSettings *settings) error {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			return fmt.Errorf("a host has no name")
		}
		if strings.ContainsAny(name, " \t\n,") {
			return fmt.Errorf("host name %q must not contain blanks or commas", name)
		}
		i, known := index[name]
		if !known {
			i = len(inv.Hosts)
			index[name] = i
			h := Host{Name: name, Address: name, Vars: map[string]any{}}
			apply(&h, f.Defaults)
			inv.Hosts = append(inv.Hosts, h)
		}
		h := &inv.Hosts[i]
		if groupSettings != nil {
			h.Groups = append(h.Groups, group)
			apply(h, *groupSettings)
		}
		if e.Address != "" {
			h.Address = e.Address
		}
		apply(h, e.settings)
		return nil
	}

	if f.Groups.Kind != 0 {
		if f.Groups.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("line %d: groups must be a mapping of group names", f.Groups.Line)
		}
		for i := 0; i+1 < len(f.Groups.Content); i += 2 {
			name := f.Groups.Content[i].Value
			if name == "" || name == "all" || strings.ContainsAny(name, " \t\n,*?[") {
				return nil, fmt.Errorf("line %d: invalid group name %q", f.Groups.Content[i].Line, name)
			}
			var g groupEntry
			if err := decodeStrict(f.Groups.Content[i+1], &g); err != nil {
				return nil, fmt.Errorf("group %s: %w", name, err)
			}
			inv.Groups = append(inv.Groups, name)
			// Group settings apply before those of the single hosts, also
			// for hosts that are listed in several groups.
			for _, e := range g.Hosts {
				if err := add(hostEntry{Name: e.Name}, name, &g.settings); err != nil {
					return nil, fmt.Errorf("group %s: %w", name, err)
				}
			}
		}
		for i := 0; i+1 < len(f.Groups.Content); i += 2 {
			var g groupEntry
			_ = f.Groups.Content[i+1].Decode(&g)
			for _, e := range g.Hosts {
				if err := add(e, "", nil); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, e := range f.Hosts {
		if err := add(e, "", nil); err != nil {
			return nil, err
		}
	}
	if len(inv.Hosts) == 0 {
		return nil, fmt.Errorf("the inventory lists no hosts")
	}
	for _, h := range inv.Hosts {
		if h.Port < 0 || h.Port > 65535 {
			return nil, fmt.Errorf("host %s: invalid port %d", h.Name, h.Port)
		}
	}
	return inv, nil
}

func apply(h *Host, s settings) {
	if s.User != nil {
		h.User = *s.User
	}
	if s.Port != nil {
		h.Port = *s.Port
	}
	if s.Become != nil {
		h.Become = *s.Become
	}
	for k, v := range s.Vars {
		h.Vars[k] = v
	}
}

// Limit keeps the hosts that match one of the comma-separated patterns: a
// group name, or a host name with * and ? as wildcards. A pattern that
// matches nothing is an error, since it is most likely a typo.
func (inv *Inventory) Limit(patterns string) ([]Host, error) {
	keep := make([]bool, len(inv.Hosts))
	for _, pattern := range strings.Split(patterns, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		matched := false
		for i, h := range inv.Hosts {
			ok, err := path.Match(pattern, h.Name)
			if err != nil {
				return nil, fmt.Errorf("invalid pattern %q", pattern)
			}
			for _, g := range h.Groups {
				ok = ok || g == pattern
			}
			if ok {
				keep[i], matched = true, true
			}
		}
		if !matched {
			known := append([]string{}, inv.Groups...)
			sort.Strings(known)
			return nil, fmt.Errorf("%q matches no host or group (groups: %s)", pattern, strings.Join(known, ", "))
		}
	}
	var hosts []Host
	for i, h := range inv.Hosts {
		if keep[i] {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

// decodeStrict decodes a node and rejects unknown keys, which are most
// likely typos.
func decodeStrict(node *yaml.Node, out any) error {
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	return nil
}
