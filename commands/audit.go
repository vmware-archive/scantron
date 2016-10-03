package commands

import (
	"fmt"

	"github.com/pivotal-cf/scantron/audit"
	"github.com/pivotal-cf/scantron/manifest"
)

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

	showReport(report)

	return nil
}

func showReport(report audit.AuditResult) {
	if report.OK() {
		fmt.Println("ok")
		return
	}

	if len(report.ExtraHosts) > 0 {
		fmt.Println("found hosts in report that were not in the manifest:")

		for _, host := range report.ExtraHosts {
			fmt.Println(host)
		}

		fmt.Println()
	}

	if len(report.MissingHostType) > 0 {
		fmt.Println("found host types in the manifest that were not found in the scan:")

		for _, host := range report.MissingHostType {
			fmt.Println(host)
		}

		fmt.Println()
	}

	for host, hostReport := range report.Hosts {
		if hostReport.OK() {
			fmt.Printf("ok  %s\n", host)
			continue
		} else {
			fmt.Printf("err %s\n", host)
		}

		if len(hostReport.UnexpectedPorts) > 0 {
			fmt.Println("  found unexpected ports:")

			for _, port := range hostReport.UnexpectedPorts {
				fmt.Printf("    %d\n", port)
			}

			fmt.Println()
		}

		if len(hostReport.MissingPorts) > 0 {
			fmt.Println("  did not find ports that were mentioned in manifest:")

			for _, port := range hostReport.MissingPorts {
				fmt.Printf("    %d\n", port)
			}

			fmt.Println()
		}

		if len(hostReport.MissingProcesses) > 0 {
			fmt.Println("  did not find processes that were mentioned in manifest:")

			for _, process := range hostReport.MissingProcesses {
				fmt.Printf("    %s\n", process)
			}

			fmt.Println()
		}

		if len(hostReport.MismatchedProcesses) > 0 {
			fmt.Println("  processes were found but there mismatches between their attributes:")

			for _, process := range hostReport.MismatchedProcesses {
				fmt.Printf("    %s: %s should be '%s' but was actually '%s'\n", process.Command,
					process.Field, process.Expected, process.Actual)
			}

			fmt.Println()
		}
	}
}
