package report

import "github.com/pivotal-cf/scantron/db"

func BuildWorldReadableFilesReport(database *db.Database) (Report, error) {
	rows, err := database.DB().Query(`
	SELECT DISTINCT h.name, f.path
    FROM hosts h
      JOIN files f
        ON h.id = f.host_id
    WHERE f.path LIKE "/var/vcap/data/jobs/%"
      AND f.permissions & 04 != 0
    ORDER BY h.name, f.path
	`)
	if err != nil {
		return Report{}, err
	}

	defer rows.Close()

	report := Report{
		Header: []string{"Identity", "Path"},
	}

	for rows.Next() {
		var (
			hostname string
			filepath string
		)

		err := rows.Scan(&hostname, &filepath)
		if err != nil {
			return Report{}, err
		}

		report.Rows = append(report.Rows, []string{
			hostname,
			filepath,
		})
	}

	return report, nil
}
