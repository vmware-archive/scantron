package commands

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/pivotal-cf/scantron/scanner"
)

const asciiCross = "\u2717"
const asciiCheckmark = "\u2713"

func showReport(results []scanner.ScannedService) error {
	wr := tabwriter.NewWriter(os.Stdout, 0, 8, 2, '\t', 0)

	fmt.Fprintln(wr, strings.Join([]string{"Host", "Job", "Service", "PID", "Port", "User", "SSL"}, "\t"))

	for _, result := range results {
		ssl := asciiCross
		if result.SSL {
			ssl = asciiCheckmark
		}

		fmt.Fprintln(wr, fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%d\t%s\t%s",
			result.IP,
			result.Hostname,
			result.Name,
			result.PID,
			result.Port,
			result.User,
			ssl),
		)
	}

	return wr.Flush()
}
