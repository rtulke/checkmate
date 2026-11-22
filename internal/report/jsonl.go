package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
)

// Event is one line of the jsonl format and one syslog message: the result
// of a check, or the summary of a run. Each event carries the host and run
// so it can be understood on its own in a log pipeline.
type Event struct {
	Time          string             `json:"time"`
	Event         string             `json:"event"` // "result" or "summary"
	Tool          string             `json:"tool"`
	Version       string             `json:"version,omitempty"`
	RunID         string             `json:"run_id,omitempty"`
	Host          string             `json:"host"`
	OS            string             `json:"os,omitempty"`
	Distro        string             `json:"distro,omitempty"`
	Policy        string             `json:"policy"`
	PolicyVersion string             `json:"policy_version,omitempty"`
	ID            string             `json:"id,omitempty"`
	Name          string             `json:"name,omitempty"`
	Status        engine.Status      `json:"status,omitempty"`
	Severity      string             `json:"severity,omitempty"`
	Tags          []string           `json:"tags,omitempty"`
	Reason        string             `json:"reason,omitempty"`
	Expected      string             `json:"expected,omitempty"`
	Reference     string             `json:"reference,omitempty"`
	Remediation   string             `json:"remediation,omitempty"`
	Waiver        *engine.WaiverInfo `json:"waiver,omitempty"`
	DurationMS    int64              `json:"duration_ms"`
	Summary       *engine.Summary    `json:"summary,omitempty"`
}

// Events returns the events of a report: one per check, then the summary.
func Events(r *engine.Report, version string) []Event {
	base := Event{
		Time:          r.Started.UTC().Format(time.RFC3339),
		Tool:          "checkmate",
		Version:       firstNonEmpty(r.Version, version),
		RunID:         r.RunID,
		Host:          r.Facts.Hostname,
		OS:            r.Facts.OS,
		Distro:        r.Facts.DistroName,
		Policy:        policyTitle(r),
		PolicyVersion: r.PolicyVersion,
	}
	events := make([]Event, 0, len(r.Results)+1)
	for _, res := range r.Results {
		e := base
		e.Event = "result"
		e.ID, e.Name, e.Status, e.Severity, e.Tags = res.ID, res.Name, res.Status, res.Severity, res.Tags
		e.Reason, e.Expected, e.Reference, e.Remediation = res.Message, res.Expected, res.Reference, res.Remediation
		e.Waiver, e.DurationMS = res.Waiver, res.DurationMS
		events = append(events, e)
	}
	e := base
	e.Event = "summary"
	summary := r.Summary
	e.Summary = &summary
	e.DurationMS = r.DurationMS
	return append(events, e)
}

func writeJSONL(w io.Writer, rs []*engine.Report, o Options) error {
	enc := json.NewEncoder(w)
	for _, r := range rs {
		for _, e := range Events(r, o.Version) {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// SyslogMessage is an event prepared for syslog.
type SyslogMessage struct {
	Severity int // RFC 5424 severity
	MsgID    string
	Text     string
}

// syslogFieldLimit keeps messages well below the size limits of syslog
// relays and UDP.
const syslogFieldLimit = 512

// SyslogMessages turns reports into syslog messages: one JSON message per
// evaluated check (skipped and not applicable checks are left out) and one
// per summary.
func SyslogMessages(rs []*engine.Report, version string) []SyslogMessage {
	var out []SyslogMessage
	for _, r := range rs {
		for _, e := range Events(r, version) {
			if e.Status == engine.StatusSkip || e.Status == engine.StatusNA {
				continue
			}
			e.Reason = clipOneLine(e.Reason, syslogFieldLimit)
			e.Expected = clipOneLine(e.Expected, syslogFieldLimit)
			e.Remediation = clipOneLine(e.Remediation, syslogFieldLimit)
			text, err := json.Marshal(e)
			if err != nil {
				continue
			}
			out = append(out, SyslogMessage{Severity: syslogSeverity(e), MsgID: e.Event, Text: string(text)})
		}
	}
	return out
}

// syslogSeverity maps a result to a syslog severity: failures by check
// severity, errors as errors, everything else as informational. A summary
// is a notice, or a warning if the host is not compliant.
func syslogSeverity(e Event) int {
	const (
		critical, errSev, warning, notice, info = 2, 3, 4, 5, 6
	)
	if e.Summary != nil {
		if e.Summary.Compliant {
			return notice
		}
		return warning
	}
	switch e.Status {
	case engine.StatusError:
		return errSev
	case engine.StatusWarn:
		return warning
	case engine.StatusFail:
		switch e.Severity {
		case "critical":
			return critical
		case "high":
			return errSev
		case "medium":
			return warning
		}
		return notice
	}
	return info
}

func clipOneLine(s string, n int) string {
	s = oneLine(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
