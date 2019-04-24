package db

import (
	"database/sql"
	"errors"
	"fmt"
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

func CreateDatabase(path string) (*Database, error) {
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		if err != nil {
			return nil, err
		}

		return nil, errors.New("database already exists")
	}

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
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	database := &Database{db: db}

	version, err := database.Version()
	if err != nil {
		return nil, err
	}

	if version != SchemaVersion {
		return nil, fmt.Errorf("The database version (%d) does not match latest version (%d). Please create a new database.", version, SchemaVersion)
	}

	return database, nil
}

func (db *Database) Close() error {
	return db.db.Close()
}

func (db *Database) Version() (int, error) {
	rows, err := db.db.Query("SELECT version FROM version")
	if err != nil {
		return -1, err
	}

	defer rows.Close()

	hasRow := rows.Next()
	if !hasRow {
		return -1, errors.New("No version record found")
	}

	var version int
	rows.Scan(&version)

	return version, nil
}

type queryFunc func() *sql.Row
type insertFunc func() (sql.Result, error)

func getIndexOrInsert(qf queryFunc, insF insertFunc) (int, error) {
	var rowId int
	err := qf().Scan(&rowId)
	if err != nil {
		if err != sql.ErrNoRows {
			return -1, err
		}

		res, err := insF()
		if err != nil {
			return -1, err
		}

		insertedID, err := res.LastInsertId()
		if err != nil {
			return -1, err
		}

		rowId = int(insertedID)
	}
	return rowId, nil
}

func (db *Database) SaveReport(deployment string, report scanner.ScanResult) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	depID, err := getIndexOrInsert(
		func() *sql.Row { return tx.QueryRow("SELECT id FROM deployments WHERE name = ?", deployment) },
		func() (sql.Result, error) { return tx.Exec("INSERT INTO deployments(name) VALUES (?)", deployment) })
	if err != nil {
		return err
	}

	for _, scan := range report.JobResults {

		hostID, err := getIndexOrInsert(
			func() *sql.Row {
				return tx.QueryRow("SELECT id FROM hosts WHERE name = ? AND ip = ?", scan.Job, scan.IP)
			},
			func() (sql.Result, error) {
				return tx.Exec("INSERT INTO hosts(name, ip, deployment_id) VALUES (?, ?, ?)", scan.Job, scan.IP, depID)
			})
		if err != nil {
			return err
		}

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
					"INSERT INTO ports(process_id, protocol, address, number, foreignAddress, foreignNumber, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
					processID, port.Protocol, port.Address, port.Number, port.ForeignAddress, port.ForeignNumber, port.State,
				)
				if err != nil {
					return err
				}

				portID, err := res.LastInsertId()
				if err != nil {
					return err
				}

				if port.TLSInformation != nil && port.TLSInformation.ScanError != nil {
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

				if port.TLSInformation != nil && port.TLSInformation.Certificate != nil {
					cert := port.TLSInformation.Certificate

					res, err = tx.Exec(`
            INSERT INTO tls_certificates (
               port_id,
               cert_expiration,
               cert_bits,
               cert_country,
               cert_province,
               cert_locality,
               cert_organization,
               cert_common_name,
               mutual
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
						portID,
						cert.Expiration,
						cert.Bits,
						cert.Subject.Country,
						cert.Subject.Province,
						cert.Subject.Locality,
						cert.Subject.Organization,
						cert.Subject.CommonName,
						port.TLSInformation.Mutual,
					)
					if err != nil {
						return err
					}

					certID, err := res.LastInsertId()
					if err != nil {
						return err
					}

					for suite, ciphers := range port.TLSInformation.CipherInformation {
						if len(ciphers) > 0 {
							suiteID, err := getIndexOrInsert(
								func() *sql.Row { return tx.QueryRow("SELECT id FROM tls_suites WHERE suite = ?", suite) },
								func() (sql.Result, error) { return tx.Exec("INSERT INTO tls_suites(suite) VALUES (?)", suite) })
							if err != nil {
								return err
							}

							for _, cipher := range ciphers {
								cipherID, err := getIndexOrInsert(
									func() *sql.Row { return tx.QueryRow("SELECT id FROM tls_ciphers WHERE cipher = ?", cipher) },
									func() (sql.Result, error) { return tx.Exec("INSERT INTO tls_ciphers(cipher) VALUES (?)", cipher) })
								if err != nil {
									return err
								}

								_, err = tx.Exec("INSERT INTO certificate_to_ciphersuite(certificate_id, suite_id, cipher_id) VALUES (?, ?, ?)", certID, suiteID, cipherID)
								if err != nil {
									return err
								}
							}
						}
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
			res, err := tx.Exec(
				"INSERT INTO files(host_id, path, permissions, user, file_group, size, modified) VALUES (?, ?, ?, ?, ?, ?, ?)",
				hostID, file.Path, file.Permissions, file.User, file.Group, file.Size, file.ModifiedTime,
			)
			if err != nil {
				return err
			}

			if len(file.RegexMatches) > 0 {
				fileID, err := res.LastInsertId()
				if err != nil {
					return err
				}

				for _, r := range file.RegexMatches {
					contentID, err := getIndexOrInsert(
						func() *sql.Row { return tx.QueryRow("SELECT id FROM regexes WHERE regex = ?", r.ContentRegex) },
						func() (sql.Result, error) { return tx.Exec("INSERT INTO regexes(regex) VALUES (?)", r.ContentRegex) })
					if err != nil {
						return err
					}

					if r.PathRegex != "" {
						pathID, err := getIndexOrInsert(
							func() *sql.Row { return tx.QueryRow("SELECT id FROM regexes WHERE regex = ?", r.PathRegex) },
							func() (sql.Result, error) { return tx.Exec("INSERT INTO regexes(regex) VALUES (?)", r.PathRegex) })
						if err != nil {
							return err
						}

						_, err = tx.Exec("INSERT INTO file_to_regex(file_id, path_regex_id, content_regex_id) VALUES (?, ?, ?)",
							fileID, pathID, contentID)
						if err != nil {
							return err
						}
					} else {
						_, err = tx.Exec("INSERT INTO file_to_regex(file_id, content_regex_id) VALUES (?, ?)",
							fileID, contentID)
						if err != nil {
							return err
						}
					}
				}
			}
		}

		for _, sshKey := range scan.SSHKeys {
			_, err = tx.Exec(
				"INSERT INTO ssh_keys(host_id, type, key) VALUES (?, ?, ?)",
				hostID, sshKey.Type, sshKey.Key,
			)
			if err != nil {
				return err
			}
		}
	}

	for _, releaseReport := range report.ReleaseResults {
		_, err := tx.Exec("INSERT INTO releases(name, version, deployment_id) VALUES (?, ?, ?)", releaseReport.Name, releaseReport.Version, depID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
