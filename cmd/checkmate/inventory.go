package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/inventory"
	"github.com/rtulke/checkmate/internal/policy"
	"github.com/rtulke/checkmate/internal/runner"
)

func inventoryHosts(path, limit string) ([]inventory.Host, error) {
	inv, err := inventory.Load(path)
	if err != nil {
		return nil, err
	}
	if limit == "" {
		return inv.Hosts, nil
	}
	return inv.Limit(limit)
}

// runInventory runs the policy on every host, forks of them at a time, and
// returns one report per host in the order of the inventory. Progress goes
// to progress, one line per finished host.
func runInventory(ctx context.Context, p *policy.Policy, hosts []inventory.Host, opts engine.Options, forks int, progress io.Writer) []*engine.Report {
	if forks < 1 {
		forks = 1
	}
	reports := make([]*engine.Report, len(hosts))
	sem := make(chan struct{}, forks)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h inventory.Host) {
			defer wg.Done()
			defer func() { <-sem }()
			r := runHost(ctx, p, h, opts)
			reports[i] = r
			mu.Lock()
			done++
			fmt.Fprintf(progress, "checkmate: [%d/%d] %s: %s\n", done, len(hosts), h.Name, hostVerdict(r))
			mu.Unlock()
		}(i, h)
	}
	wg.Wait()
	return reports
}

func runHost(ctx context.Context, p *policy.Policy, h inventory.Host, opts engine.Options) *engine.Report {
	started := time.Now()
	// unchecked is the report of a host nothing is known about.
	unchecked := func(err error) *engine.Report {
		return &engine.Report{
			Tool:        "checkmate",
			Policy:      p.Name,
			PolicyPath:  p.Path,
			Facts:       facts.Facts{Hostname: h.Name},
			Started:     started,
			DurationMS:  time.Since(started).Milliseconds(),
			Summary:     engine.Summary{Score: -1},
			Results:     []engine.Result{},
			Host:        h.Name,
			Groups:      h.Groups,
			Error:       err.Error(),
			Unreachable: errors.Is(err, runner.ErrUnreachable),
		}
	}

	target, hostFacts, err := connectHost(ctx, h)
	if err != nil {
		return unchecked(err)
	}
	defer target.Close()
	vars := hostVars(h, opts.Vars)
	opts.Vars = vars
	opts.Facts = hostFacts
	opts.Target = target

	r := engine.Run(ctx, p, opts)
	r.Host = h.Name
	r.Groups = h.Groups
	return r
}

func hostVerdict(r *engine.Report) string {
	switch {
	case r.Unreachable:
		return "unreachable"
	case r.Error != "":
		return "not checked"
	case r.Summary.Evaluated == 0:
		return "nothing evaluated"
	case r.Summary.Compliant:
		return "compliant"
	}
	return "not compliant"
}

// connectHost prepares the connection to a host and asks it for its facts.
// The caller closes the target.
func connectHost(ctx context.Context, h inventory.Host) (*runner.Target, facts.Facts, error) {
	target, err := runner.NewTarget(h.Destination(), h.Port, h.Become)
	if err != nil {
		return nil, facts.Facts{}, err
	}
	target.Device = h.Device
	if err := target.Open(); err != nil {
		return nil, facts.Facts{}, err
	}
	hostFacts, err := target.Facts(ctx)
	if err != nil {
		target.Close()
		return nil, facts.Facts{}, err
	}
	if h.Device != "" {
		hostFacts.Hostname = h.Name
	}
	return target, hostFacts, nil
}

// hostVars are the variables of a run on a host: those of the inventory
// override the policy, the command line overrides both.
func hostVars(h inventory.Host, extra map[string]any) map[string]any {
	vars := map[string]any{}
	for k, v := range h.Vars {
		vars[k] = v
	}
	groups := make([]any, len(h.Groups))
	for i, g := range h.Groups {
		groups[i] = g
	}
	vars["inventory_hostname"] = h.Name
	vars["group_names"] = groups
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

// preview is what would run on one host.
type preview struct {
	host   inventory.Host
	facts  facts.Facts
	checks []*policy.Check
	errs   []*policy.CheckError
	err    error // the host could not be asked for its facts
}

// previewHosts expands the policy for every host without running a check.
// The hosts are asked for their facts, which decide which variant of a
// command applies; fromInventory adds the inventory variables.
func previewHosts(ctx context.Context, p *policy.Policy, hosts []inventory.Host, extra map[string]any, fromInventory bool, forks int) []preview {
	if forks < 1 {
		forks = 1
	}
	previews := make([]preview, len(hosts))
	sem := make(chan struct{}, forks)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h inventory.Host) {
			defer wg.Done()
			defer func() { <-sem }()
			pv := preview{host: h}
			target, hostFacts, err := connectHost(ctx, h)
			if err != nil {
				pv.err = err
				previews[i] = pv
				return
			}
			target.Close()
			vars := extra
			if fromInventory {
				vars = hostVars(h, extra)
			}
			pv.facts = hostFacts
			pv.checks, pv.errs = policy.Expand(p, hostFacts, vars)
			previews[i] = pv
		}(i, h)
	}
	wg.Wait()
	return previews
}
