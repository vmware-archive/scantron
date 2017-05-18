package commands

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
)

type ReportCommand struct {
	Database string `long:"database" description:"path to report database" required:"true" value-name:"PATH"`
}

func (command *ReportCommand) Execute(args []string) error {
	db, err := db.OpenDatabase(command.Database)
	if err != nil {
		return err
	}

	rootReport, err := report.BuildRootProcessesReport(db)
	if err != nil {
		return err
	}

	tlsReport, err := report.BuildTLSViolationsReport(db)
	if err != nil {
		return err
	}

	printReport(rootReport, "Externally-accessible processes running as root:")
	printReport(tlsReport, "Processes using non-approved protocols or cipher suites:")

	return nil
}

func printReport(r report.Report, title string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(r.Header)
	table.AppendBulk(r.Rows)

	fmt.Println(title)
	fmt.Println("")
	table.Render()
	fmt.Println("")
	fmt.Println("")
}
