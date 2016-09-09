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

		if len(result.Cmd.Args) > 0 {
			fmt.Fprintln(wr, fmt.Sprintf("Args: %s", result.Cmd.Args))
		}

		if len(result.Cmd.Env) > 0 {
			fmt.Fprintf(wr, fmt.Sprintf("Envs: { "))
			for _, env := range result.Cmd.Env {
				if len(env) == 0 {
					continue
				}
				fmt.Fprintf(wr, fmt.Sprintf("{%s} ", env))
			}
			fmt.Fprintf(wr, fmt.Sprintf("}\n"))
		}
	}

	return wr.Flush()
}

func tlsReport(service scanner.ScannedService) string {
	if !service.TLSInformation.Presence {
		return asciiCross
	}

	output := bytes.NewBufferString(asciiCheckmark)
	output.WriteString(" ")

	cert := service.TLSInformation.Certificate
	if cert == nil {
		output.WriteString("(no certificate information found; maybe mutual tls?) ")
	} else {
		output.WriteString(fmt.Sprintf(
			"(size: %d, expires: %s, subject: %s) ",
			cert.Bits,
			cert.Expiration,
			cert.Subject,
		))
	}

	cipherInfo := service.TLSInformation.CipherInformation
	if len(cipherInfo) > 0 {
		for tlsVersion, ciphers := range cipherInfo {
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
