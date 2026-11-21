package policy

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// CommandSpec is a command as written in a policy. It takes one of three
// forms:
//
//	run: systemctl is-active sshd              # a plain command
//	run: { use: pkg_installed, arg: sshd }     # a snippet reference
//	run:                                       # platform variants
//	  rhel: rpm -q sshd
//	  debian,ubuntu: dpkg -s openssh-server
//	  default: echo unsupported; exit 1
type CommandSpec struct {
	Command  string
	Variants map[string]string // platform key -> command
	Use      string            // snippet name
	Arg      any               // snippet argument, available as {{ arg }}
	Args     map[string]any    // named snippet arguments, available as {{ args.x }}
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *CommandSpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		c.Command = node.Value
		return nil
	case yaml.MappingNode:
		if hasKey(node, "use") {
			var ref struct {
				Use  string         `yaml:"use"`
				Arg  any            `yaml:"arg"`
				Args map[string]any `yaml:"args"`
			}
			if err := decodeStrict(node, &ref); err != nil {
				return err
			}
			if ref.Use == "" {
				return fmt.Errorf("line %d: use: snippet name is empty", node.Line)
			}
			c.Use, c.Arg, c.Args = ref.Use, ref.Arg, ref.Args
			return nil
		}
		variants := map[string]string{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if value.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: platform variant %q must be a command string", value.Line, key.Value)
			}
			for _, k := range strings.Split(key.Value, ",") {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				if _, dup := variants[k]; dup {
					return fmt.Errorf("line %d: platform %q is listed twice", key.Line, k)
				}
				variants[k] = value.Value
			}
		}
		if len(variants) == 0 {
			return fmt.Errorf("line %d: command has no platform variants", node.Line)
		}
		c.Variants = variants
		return nil
	}
	return fmt.Errorf("line %d: a command must be a string, a snippet reference or platform variants", node.Line)
}

// IsZero reports whether no command was given.
func (c CommandSpec) IsZero() bool {
	return c.Command == "" && len(c.Variants) == 0 && c.Use == ""
}

// Select picks the command for the given platform keys (most specific
// first). ok is false if no variant applies to this platform.
func (c CommandSpec) Select(platformKeys []string) (cmd string, ok bool) {
	if len(c.Variants) == 0 {
		return c.Command, true
	}
	for _, key := range platformKeys {
		if v, found := c.Variants[key]; found {
			return v, true
		}
	}
	return "", false
}

// Platforms lists the platform keys of a variant command.
func (c CommandSpec) Platforms() []string {
	keys := make([]string, 0, len(c.Variants))
	for k := range c.Variants {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func hasKey(node *yaml.Node, key string) bool {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return true
		}
	}
	return false
}

// decodeStrict decodes a node and rejects unknown keys.
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
