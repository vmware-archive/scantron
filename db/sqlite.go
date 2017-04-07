package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	// Include SQLite3 for database.
	_ "github.com/mattn/go-sqlite3"

	"github.com/pivotal-cf/scantron/scanner"
)

type Database struct {
	db *sql.DB
}

func (d *Database) DB() *sql.DB {
	return d.db
}

func OpenOrCreateDatabase(path string) (*Database, error) {
	_, err := os.Stat(path)

	if os.IsNotExist(err) {
		return CreateDatabase(path)
	} else {
		return OpenDatabase(path)
	}
}

func CreateDatabase(path string) (*Database, error) {
	database, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	_, err = database.Exec(createDDL, SchemaVersion)
	if err != nil {
		return nil, err
	}

	return &Database{db: database}, nil
}

func OpenDatabase(path string) (*Database, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	database := &Database{db: db}

	version := database.Version()

	if version != SchemaVersion {
		return nil, fmt.Errorf("The database version (%d) does not match latest version (%d). Please create a new database.", version, SchemaVersion)
	}

	return database, nil
}

func (db *Database) Close() error {
	return db.db.Close()
}

func (db *Database) Version() int {
	rows, err := db.db.Query("SELECT version FROM version")
	if err != nil {
		return 0
	}

	defer rows.Close()

	hasRow := rows.Next()
	if !hasRow {
		return 0
	}

	var version int
	rows.Scan(&version)

	return version
}

func (db *Database) SaveReport(scans []scanner.ScanResult) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO reports(timestamp) VALUES (?)", time.Now())
	if err != nil {
		return err
	}

	insertedID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	reportID := int(insertedID)

	for _, scan := range scans {
		var hostID int
		query := "SELECT id FROM hosts WHERE name = ? AND ip = ? AND report_id = ?"
		err := tx.QueryRow(query, scan.Job, scan.IP, reportID).Scan(&hostID)
		if err != nil {
			if err != sql.ErrNoRows {
				return err
			}

			res, err = tx.Exec("INSERT INTO hosts(name, ip, report_id) VALUES (?, ?, ?)", scan.Job, scan.IP, reportID)
			if err != nil {
				return err
			}

			insertedID, err = res.LastInsertId()
			if err != nil {
				return err
			}

			hostID = int(insertedID)

			for _, service := range scan.Services {
				cmdline := strings.Join(service.Cmdline, " ")
				res, err := tx.Exec(
					"INSERT INTO processes(host_id, name, pid, cmdline, user) VALUES (?, ?, ?, ?, ?)",
					hostID, service.CommandName, service.PID, cmdline, service.User,
				)
				if err != nil {
					return err
				}

				processID, err := res.LastInsertId()
				if err != nil {
					return err
				}

				for _, port := range service.Ports {
					res, err = tx.Exec(
						"INSERT INTO ports(process_id, protocol, address, number, state) VALUES (?, ?, ?, ?, ?)",
						processID, port.Protocol, port.Address, port.Number, port.State,
					)
					if err != nil {
						return err
					}

					portID, err := res.LastInsertId()
					if err != nil {
						return err
					}

					if port.TLSInformation.ScanError != nil {
						_, err = tx.Exec(`
						INSERT INTO tls_scan_errors (
							 port_id,
							 cert_scan_error
						) VALUES (?, ?)`,
							portID,
							port.TLSInformation.ScanError.Error(),
						)
						if err != nil {
							return err
						}
					}

					if port.TLSInformation.Certificate != nil {
						cert := port.TLSInformation.Certificate

						_, err = tx.Exec(`
						INSERT INTO tls_informations (
							 port_id,
							 cert_expiration,
							 cert_bits,
							 cert_country,
							 cert_province,
							 cert_locality,
							 cert_organization,
							 cert_common_name
						 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
							portID,
							cert.Expiration,
							cert.Bits,
							cert.Subject.Country,
							cert.Subject.Province,
							cert.Subject.Locality,
							cert.Subject.Organization,
							cert.Subject.CommonName,
						)
						if err != nil {
							return err
						}
					}
				}

				_, err = tx.Exec("INSERT INTO env_vars(var, process_id) VALUES (?, ?)",
					strings.Join(service.Env, " "), processID,
				)
				if err != nil {
					return err
				}
			}

			for _, file := range scan.Files {
				_, err = tx.Exec(
					"INSERT INTO files(host_id, path, permissions) VALUES (?, ?, ?)",
					hostID, file.Path, file.Permissions,
				)
				if err != nil {
					return err
				}
			}
		}
	}

	return tx.Commit()
}

// Update the schema version when the DDL changes
const SchemaVersion = 1

const createDDL = `
CREATE TABLE reports (
	id integer PRIMARY KEY AUTOINCREMENT,
	timestamp datetime,
	UNIQUE(timestamp)
);

CREATE TABLE hosts (
	id integer PRIMARY KEY AUTOINCREMENT,
	report_id integer,
	name text,
	ip text,
	UNIQUE(ip, name, report_id)
	FOREIGN KEY(report_id) REFERENCES reports(id)
);

CREATE TABLE processes (
	id integer PRIMARY KEY AUTOINCREMENT,
	host_id integer,
	name text,
	pid integer,
	cmdline text,
	user text,
	FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE ports (
	id integer PRIMARY KEY AUTOINCREMENT,
	process_id integer,
  protocol string,
  address string,
	number integer,
	state string,
	FOREIGN KEY(process_id) REFERENCES processes(id)
);

CREATE TABLE tls_informations (
	id integer PRIMARY KEY AUTOINCREMENT,
	port_id integer,
	cert_expiration datetime,
	cert_bits integer,
	cert_country string,
	cert_province string,
	cert_locality string,
	cert_organization string,
	cert_common_name string,
	FOREIGN KEY(port_id) REFERENCES ports(id)
);

CREATE TABLE tls_scan_errors (
	id integer PRIMARY KEY AUTOINCREMENT,
	port_id integer,
	cert_scan_error string,
	FOREIGN KEY(port_id) REFERENCES ports(id)
);

CREATE TABLE env_vars (
	id integer PRIMARY KEY AUTOINCREMENT,
	process_id integer,
	var text,
	FOREIGN KEY(process_id) REFERENCES processes(id)
);

CREATE TABLE files (
	id integer PRIMARY KEY AUTOINCREMENT,
	host_id integer,
	path text,
	permissions integer,
	FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE version (
	version integer
);

INSERT INTO version(version) VALUES(?);
`
