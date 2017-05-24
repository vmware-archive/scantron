package commands

import (
	"errors"
	"os"

	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
)

type ReportCommand struct {
	Database string `long:"database" description:"path to report database" required:"true" value-name:"PATH"`
}

func (command *ReportCommand) Execute(args []string) error {
	database, err := db.OpenDatabase(command.Database)
	if err != nil {
		return err
	}

	rootReport, err := report.BuildRootProcessesReport(database)
	if err != nil {
		return err
	}

	tlsReport, err := report.BuildTLSViolationsReport(database)
	if err != nil {
		return err
	}

	filesReport, err := report.BuildWorldReadableFilesReport(database)
	if err != nil {
		return err
	}

	sshKeysReport, err := report.BuildInsecureSshKeyReport(database)
	if err != nil {
		return err
	}

	rootReport.WriteTo(os.Stdout)
	tlsReport.WriteTo(os.Stdout)
	filesReport.WriteTo(os.Stdout)
	sshKeysReport.WriteTo(os.Stdout)

	if !rootReport.IsEmpty() ||
		!tlsReport.IsEmpty() ||
		!filesReport.IsEmpty() ||
		!sshKeysReport.IsEmpty() {
		return errors.New("Violations were found!")
	}

	return nil
}
