package commands

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/pivotal-cf/scantron/db"
)

type ReportCommand struct {
	Database string `long:"database" description:"path to report database" required:"true" value-name:"PATH"`
}

func (command *ReportCommand) Execute(args []string) error {
	db, err := db.OpenDatabase(command.Database)
	if err != nil {
		return err
	}

	err = rootProcessReport(db)
	if err != nil {
		return err
	}

	return nil
}

func rootProcessReport(db *db.Database) error {
	rows, err := db.DB().Query(`
		SELECT DISTINCT h.name, po.number, pr.name
        FROM hosts h
        JOIN processes pr
        ON h.id = pr.host_id
        JOIN ports po
        ON po.process_id = pr.id
        WHERE po.state = "LISTEN"
        AND po.address != "127.0.0.1"
        AND pr.user = "root"
        AND pr.name NOT IN ('sshd', 'rpcbind')
        ORDER BY h.name, po.number
	`)
	if err != nil {
		return err
	}

	defer rows.Close()

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Hostname", "Port", "Process Name"})

	for rows.Next() {
		var (
			hostname    string
			processName string
			portNumber  int
		)

		err := rows.Scan(&hostname, &portNumber, &processName)
		if err != nil {
			return err
		}

		table.Append([]string{
			hostname,
			fmt.Sprintf("%d", portNumber),
			processName,
		})

	}
	fmt.Println("Processes Running as Root:")

	table.Render()

	return nil
}
