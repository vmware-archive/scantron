package audit

import (
	"bytes"
	"database/sql"
	"io"

	"github.com/pivotal-cf/scantron/manifest"
	yaml "gopkg.in/yaml.v2"
)

func GenerateManifest(writer io.Writer, db *sql.DB) error {
	m := manifest.Manifest{}

	specs, err := getSpecsFor(db)
	if err != nil {
		return err
	}
	m.Specs = specs

	bs, err := yaml.Marshal(m)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, bytes.NewReader(bs))
	return err
}

func getSpecsFor(db *sql.DB) ([]manifest.Spec, error) {
	rows, err := db.Query(`SELECT hosts.id, hosts.name FROM hosts`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var hostId int
	var hostName string
	var specs []manifest.Spec

	for rows.Next() {
		err := rows.Scan(&hostId, &hostName)
		if err != nil {
			return nil, err
		}

		spec := manifest.Spec{
			Prefix: hostName,
		}

		processes, err := getProcessesFor(db, hostId)
		if err != nil {
			return nil, err
		}

		spec.Processes = processes
		specs = append(specs, spec)
	}

	return specs, nil
}

func getProcessesFor(db *sql.DB, hostId int) ([]manifest.Process, error) {
	processes := []manifest.Process{}

	processRows, err := db.Query(`
		SELECT DISTINCT processes.user, processes.name, processes.id
			FROM processes
				JOIN ports
					ON processes.id = ports.process_id
			WHERE processes.host_id = ?
				AND ports.address != "127.0.0.1"
				AND ports.state = "LISTEN"
		`, hostId)
	if err != nil {
		return nil, err
	}

	defer processRows.Close()

	var processUser, processName string

	for processRows.Next() {
		var processId int
		err := processRows.Scan(&processUser, &processName, &processId)
		if err != nil {
			return nil, err
		}

		process := manifest.Process{
			Command: processName,
			User:    processUser,
		}
		ports, err := getPortsFor(db, processId)
		if err != nil {
			return nil, err
		}

		process.Ports = ports
		processes = append(processes, process)
	}

	return processes, nil
}

func getPortsFor(db *sql.DB, processId int) ([]manifest.Port, error) {
	ports := []manifest.Port{}

	rows, err := db.Query(`
		SELECT ports.number
		FROM ports
		WHERE ports.process_id = ?
			AND ports.address != "127.0.0.1"
			AND ports.state = "LISTEN"
	`, processId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var portNumber manifest.Port

	for rows.Next() {
		err := rows.Scan(&portNumber)
		if err != nil {
			return nil, err
		}

		ports = append(ports, portNumber)
	}

	return ports, nil
}
