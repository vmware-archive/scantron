package report

import "github.com/pivotal-cf/scantron/db"

func BuildInsecureSshKeyReport(database *db.Database) (Report, error) {
	rows, err := database.DB().Query(`
    SELECT h.name
    FROM ssh_keys s1
      CROSS JOIN ssh_keys s2
      JOIN hosts h
        ON s1.host_id = h.id
    WHERE s1.key = s2.key
      AND s1.id != s2.id
    ORDER BY h.name
    `)
	if err != nil {
		return Report{}, err
	}

	defer rows.Close()

	report := Report{
		Header: []string{"Identity"},
	}

	for rows.Next() {
		var hostname string

		err := rows.Scan(&hostname)
		if err != nil {
			return Report{}, err
		}

		report.Rows = append(report.Rows, []string{
			hostname,
		})
	}

	return report, nil
}
