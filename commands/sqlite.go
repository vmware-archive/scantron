package commands

import (
	"database/sql"
	"errors"
	"os"
	"strings"

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

func OpenOrCreateDatabase(path string, shouldAppend bool) (*Database, error) {
	_, err := os.Stat(path)
	fileExists := !os.IsNotExist(err)

	if fileExists && !shouldAppend {
		return nil, errors.New(path + " already exists")
	}

	var db *Database
	if shouldAppend && fileExists {
		db, err = OpenDatabase(path)
	} else {
		db, err = CreateDatabase(path)
	}

	return db, err
}

func CreateDatabase(path string) (*Database, error) {
	db, err := OpenDatabase(path)
	if err != nil {
		return nil, err
	}

	_, err = db.db.Exec(createDDL)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func OpenDatabase(path string) (*Database, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	return &Database{
		db: db,
	}, nil
}

func (db *Database) Close() error {
	return db.db.Close()
}

func (db *Database) SaveReport(scans []scanner.ScanResult) error {
	for _, scan := range scans {
		var hostID int
		query := "SELECT id FROM hosts WHERE name = ? AND ip = ?"
		err := db.db.QueryRow(query, scan.Job, scan.IP).Scan(&hostID)
		if err != nil {
			if err != sql.ErrNoRows {
				return err
			}

			res, err := db.db.Exec("INSERT INTO hosts(name, ip) VALUES (?, ?)", scan.Job, scan.IP)
			if err != nil {
				return err
			}

			insertedID, err := res.LastInsertId()
			if err != nil {
				return err
			}

			hostID = int(insertedID)

			for _, service := range scan.Services {
				cmdline := strings.Join(service.Cmdline, " ")
				res, err := db.db.Exec(
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
					res, err = db.db.Exec(
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
						_, err = db.db.Exec(`
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

						_, err = db.db.Exec(`
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

				_, err = db.db.Exec("INSERT INTO env_vars(var, process_id) VALUES (?, ?)",
					strings.Join(service.Env, " "), processID,
				)
				if err != nil {
					return err
				}
			}

			for _, file := range scan.Files {
				_, err = db.db.Exec(
					"INSERT INTO files(host_id, path) VALUES (?, ?)",
					hostID, file.Path,
				)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

var createDDL = `
CREATE TABLE hosts (
	id integer PRIMARY KEY AUTOINCREMENT,
	name text,
	ip text,
	UNIQUE(ip, name)
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
	FOREIGN KEY(host_id) REFERENCES hosts(id)
);
`
