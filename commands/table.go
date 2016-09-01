package commands

import (
	"bytes"
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

	output := bytes.NewBufferString(asciiCheckmark)
	output.WriteString(" ")

	if service.TLSCert == nil {
		output.WriteString("(no certificate information found; maybe mutual tls?) ")
	} else {
		cert := service.TLSCert
		output.WriteString(fmt.Sprintf(
			"(size: %d, expires: %s, subject: %s) ",
			cert.Bits,
			cert.Expiration,
			cert.Subject,
		))
	}

	if len(service.SSLInformation) > 0 {
		for tlsVersion, ciphers := range service.SSLInformation {
			output.WriteString("(")
			output.WriteString(tlsVersion)
			output.WriteString(": [")

			for _, cipher := range ciphers {
				output.WriteString(cipher.Name)
				output.WriteString(" - ")
				output.WriteString(cipher.Quality)
				output.WriteString(" ")
			}

			output.WriteString("]) ")
		}
	}

	return output.String()
}
