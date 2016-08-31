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
		ssl := tlsReport(result)

		fmt.Fprintln(wr, fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%d\t%s\t%s",
			result.IP,
			result.Job,
			result.Name,
			result.PID,
			result.Port,
			result.User,
			ssl),
		)
	}

	return wr.Flush()
}

func tlsReport(service scanner.ScannedService) string {
	if !service.SSL {
		return asciiCross
	}

	if service.TLSCert == nil {
		return fmt.Sprintf("%s (no certificate information found; maybe mutual tls?)", asciiCheckmark)
	}

	cert := service.TLSCert
	return fmt.Sprintf(
		"%s (size: %d, expires: %s, subject: %s)",
		asciiCheckmark,
		cert.Bits,
		cert.Expiration,
		cert.Subject,
	)
}
