package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
)

var csvHeader = []string{
	"host", "os", "distro", "policy", "policy_version", "started", "run_id",
	"id", "name", "status", "severity", "tags", "reason", "expected",
	"waiver_reason", "waiver_until", "waived_status", "reference", "remediation",
	"duration_ms", "location",
}

// writeCSV writes one row per check and report. Cells that a spreadsheet
// would read as a formula are prefixed with a single quote, since check
// output can contain text from the inspected host.
func writeCSV(w io.Writer, rs []*engine.Report, _ Options) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range rs {
		for i := range r.Results {
			res := &r.Results[i]
			var reason, until string
			if res.Waiver != nil {
				reason, until = res.Waiver.Reason, res.Waiver.Until
			}
			row := []string{
				r.Facts.Hostname, r.Facts.OS, r.Facts.DistroName, policyTitle(r), r.PolicyVersion,
				r.Started.Format(time.RFC3339), r.RunID,
				res.ID, res.Name, string(res.Status), res.Severity, strings.Join(res.Tags, " "),
				res.Message, res.Expected, reason, until, waiverOrigin(res), res.Reference,
				res.Remediation, strconv.FormatInt(res.DurationMS, 10), res.Location,
			}
			for j := range row {
				row[j] = csvSafe(row[j])
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralizes cells that spreadsheets evaluate as formulas.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
