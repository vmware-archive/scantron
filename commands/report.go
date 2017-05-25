package commands

import (
	"errors"
	"os"
	"path/filepath"

	"encoding/csv"

	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/report"
)

type ReportCommand struct {
	Database      string `long:"database" description:"path to report database" required:"true" value-name:"DB PATH"`
	CsvExportPath string `long:"csv" description:"path to csv output" value-name:"CSV PATH"`
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

	if command.CsvExportPath != "" {
		_, err = os.Stat(command.CsvExportPath)

		if os.IsNotExist(err) {
			err = os.Mkdir(command.CsvExportPath, 0700)
			if err != nil {
				return err
			}
		}

		err = exportCsv(command.CsvExportPath, rootReport, "root_process_report.csv")
		if err != nil {
			return err
		}

		err = exportCsv(command.CsvExportPath, tlsReport, "tls_violation_report.csv")
		if err != nil {
			return err
		}

		err = exportCsv(command.CsvExportPath, filesReport, "world_readable_files_report.csv")
		if err != nil {
			return err
		}

		err = exportCsv(command.CsvExportPath, sshKeysReport, "insecure_sshkey_report.csv")
		if err != nil {
			return err
		}
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

func exportCsv(absDir string, report report.Report, reportFileName string) error {
	f, err := os.Create(filepath.Join(absDir, reportFileName))
	if err != nil {
		return err
	}

	err = f.Chmod(0600)
	if err != nil {
		return err
	}

	csvWriter := csv.NewWriter(f)
	csvWriter.Write(report.Header)
	csvWriter.WriteAll(report.Rows)
	f.Sync()
	csvWriter.Flush()

	return nil
}
