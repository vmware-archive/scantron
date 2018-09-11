package db

import (
  "database/sql"
  "encoding/json"
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

func (db *Database) Version() (int,error) {
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

func (db *Database) SaveReport(deployment string, report scanner.ScanResult) error {
  tx, err := db.db.Begin()
  if err != nil {
    return err
  }
  defer tx.Rollback()

  var depID int
  depQuery := "SELECT id FROM deployments WHERE name = ?"
  err = tx.QueryRow(depQuery, deployment).Scan(&depID)
  if err != nil {
    if err != sql.ErrNoRows {
      return err
    }

    res, err := tx.Exec("INSERT INTO deployments(name) VALUES (?)", deployment)
    if err != nil {
      return err
    }

    insertedID, err := res.LastInsertId()
    if err != nil {
      return err
    }

    depID = int(insertedID)
  }

  for _, scan := range report.JobResults {

    var hostID int
    query := "SELECT id FROM hosts WHERE name = ? AND ip = ?"
    err = tx.QueryRow(query, scan.Job, scan.IP).Scan(&hostID)
    if err != nil {
      if err != sql.ErrNoRows {
        return err
      }

      res, err := tx.Exec("INSERT INTO hosts(name, ip, deployment_id) VALUES (?, ?, ?)", scan.Job, scan.IP, depID)
      if err != nil {
        return err
      }

      insertedID, err := res.LastInsertId()
      if err != nil {
        return err
      }

      hostID = int(insertedID)
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

          ciJson, err := json.Marshal(port.TLSInformation.CipherInformation)
          if err != nil {
            return err
          }

          _, err = tx.Exec(`
            INSERT INTO tls_informations (
               port_id,
               cert_expiration,
               cert_bits,
               cert_country,
               cert_province,
               cert_locality,
               cert_organization,
               cert_common_name,
               cipher_suites,
               mutual
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            portID,
            cert.Expiration,
            cert.Bits,
            cert.Subject.Country,
            cert.Subject.Province,
            cert.Subject.Locality,
            cert.Subject.Organization,
            cert.Subject.CommonName,
            string(ciJson),
            port.TLSInformation.Mutual,
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
