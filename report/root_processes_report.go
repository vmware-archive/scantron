package report

import (
	"fmt"
	"github.com/pivotal-cf/scantron/db"
)

func BuildRootProcessesReport(database *db.Database) (Report, error) {
	rows, err := database.DB().Query(`
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
		return Report{}, err
	}

	defer rows.Close()

	report := Report{
		Title:  "Externally-accessible processes running as root:",
		Header: []string{"Identity", "Port", "Process Name"},
	}

	for rows.Next() {
		var (
			hostname    string
			processName string
			portNumber  int
		)

		err := rows.Scan(&hostname, &portNumber, &processName)
		if err != nil {
			return Report{}, err
		}

		report.Rows = append(report.Rows, []string{
			hostname,
			fmt.Sprintf("%d", portNumber),
			processName,
		})
	}

	return report, nil
}
