package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/pivotal-cf/scantron/audit"
	"github.com/pivotal-cf/scantron/manifest"
)

var AuditError = ExitStatusError{message: "audit mismatch", exitStatus: 3}

type AuditCommand struct {
	Database string `long:"database" description:"path to report database" value-name:"PATH" default:"./database.db"`
	Manifest string `long:"manifest" description:"path to manifest" required:"true" value-name:"PATH"`
}

func (command *AuditCommand) Execute(args []string) error {
	man, err := manifest.Parse(command.Manifest)
	if err != nil {
		return err
	}

	db, err := OpenDatabase(command.Database)
	if err != nil {
		return err
	}

	report, err := audit.Audit(db.DB(), man)
	if err != nil {
		return err
	}

	return ShowReport(os.Stdout, report)
}

func ShowReport(output io.Writer, report audit.AuditResult) error {
	if report.OK() {
		fmt.Fprintln(output, "ok")
		return nil
	}

	if len(report.ExtraHosts) > 0 {
		fmt.Fprintln(output, "found hosts in report that were not matched in the manifest:")

		for _, host := range report.ExtraHosts {
			fmt.Fprintln(output, host)
		}

		fmt.Fprintln(output)
	}

	if len(report.MissingHostType) > 0 {
		fmt.Fprintln(output, "found host types in the manifest that were not found in the scan:")

		for _, host := range report.MissingHostType {
			fmt.Fprintln(output, host)
		}

		fmt.Fprintln(output)
	}

	for host, hostReport := range report.Hosts {
		if hostReport.OK() {
			fmt.Fprintf(output, "ok  %s\n", host)
			continue
		} else {
			fmt.Fprintf(output, "err %s\n", host)
		}

		if len(hostReport.UnexpectedPorts) > 0 {
			fmt.Fprintln(output, "  found unexpected ports:")

			for _, port := range hostReport.UnexpectedPorts {
				fmt.Fprintf(output, "    %d\n", port)
			}

			fmt.Fprintln(output)
		}

		if len(hostReport.MissingPorts) > 0 {
			fmt.Fprintln(output, "  did not find ports that were mentioned in manifest:")

			for _, port := range hostReport.MissingPorts {
				fmt.Fprintf(output, "    %d\n", port)
			}

			fmt.Fprintln(output)
		}

		if len(hostReport.MissingProcesses) > 0 {
			fmt.Fprintln(output, "  did not find processes that were mentioned in manifest:")

			for _, process := range hostReport.MissingProcesses {
				fmt.Fprintf(output, "    %s\n", process)
			}

			fmt.Fprintln(output)
		}

		if len(hostReport.MismatchedProcesses) > 0 {
			fmt.Fprintln(output, "  processes were found but there mismatches between their attributes:")

			for _, process := range hostReport.MismatchedProcesses {
				fmt.Fprintf(output, "    %s: %s should be '%s' but was actually '%s'\n", process.Command,
					process.Field, process.Expected, process.Actual)
			}

			fmt.Fprintln(output)
		}
	}

	return AuditError
}
