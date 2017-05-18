package commands

import (
	"fmt"

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

	var (
		hostname    string
		processName string
		portNumber  int
	)

	fmt.Println("Processes Running as Root:")

	for rows.Next() {
		err := rows.Scan(&hostname, &portNumber, &processName)
		if err != nil {
			return err
		}

		fmt.Printf("%s, %d, %s\n", hostname, portNumber, processName)
	}

	return nil
}
