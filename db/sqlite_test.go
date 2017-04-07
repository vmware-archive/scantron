package db_test

import (
	"database/sql"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/scanner"
	"github.com/pivotal-cf/scantron/tlsscan"
)

var _ = Describe("Sqlite", func() {
	var (
		tmpdir string
		dbPath string
	)

	BeforeEach(func() {
		var err error

		tmpdir, err = ioutil.TempDir("", "scantron_db")
		Expect(err).NotTo(HaveOccurred())

		dbPath = filepath.Join(tmpdir, "database.db")
	})

	AfterEach(func() {
		os.RemoveAll(tmpdir)
	})

	Describe("OpenOrCreateDatabase", func() {
		It("creates a new database file", func() {
			database, err := db.OpenOrCreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer database.Close()

			Expect(dbPath).To(BeAnExistingFile())
		})

		It("creates the required tables", func() {
			database, err := db.OpenOrCreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer database.Close()

			sqliteDB, err := sql.Open("sqlite3", dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer sqliteDB.Close()

			tables := []string{}

			rows, err := sqliteDB.Query(`
				SELECT name
				FROM sqlite_master
				WHERE type = 'table'
					AND name NOT LIKE 'sqlite_%'`,
			)
			Expect(err).NotTo(HaveOccurred())
			defer rows.Close()

			var table string
			for rows.Next() {
				err = rows.Scan(&table)
				Expect(err).NotTo(HaveOccurred())

				tables = append(tables, table)
			}

			Expect(tables).To(ConsistOf(
				"reports",
				"hosts",
				"processes",
				"ports",
				"files",
				"tls_informations",
				"tls_scan_errors",
				"env_vars",
				"version",
			))
		})

		It("sets the schema version", func() {
			database, err := db.OpenOrCreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer database.Close()

			Expect(database.Version()).To(Equal(db.SchemaVersion))
		})

		It("returns an error when the database version is unknown", func() {
			database, err := db.OpenOrCreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			database.Close()

			sqliteDB, err := sql.Open("sqlite3", dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer sqliteDB.Close()

			_, err = sqliteDB.Exec("DROP TABLE version")
			Expect(err).NotTo(HaveOccurred())

			database, err = db.OpenOrCreateDatabase(dbPath)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("The database version (0) does not match latest version"))
		})

		It("returns an error when the database version is old", func() {
			database, err := db.OpenOrCreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			database.Close()

			sqliteDB, err := sql.Open("sqlite3", dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer sqliteDB.Close()

			_, err = sqliteDB.Exec("UPDATE version SET version = -42")
			Expect(err).NotTo(HaveOccurred())

			database, err = db.OpenOrCreateDatabase(dbPath)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("The database version (-42) does not match latest version"))
		})
	})

	Describe("SaveReport", func() {
		var (
			database       *db.Database
			hosts          []scanner.ScanResult
			host           scanner.ScanResult
			sqliteDB       *sql.DB
			certExpiration time.Time
		)

		JustBeforeEach(func() {
			var err error
			database, err = db.CreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())

			err = database.SaveReport(hosts)
			Expect(err).NotTo(HaveOccurred())

			sqliteDB, err = sql.Open("sqlite3", dbPath)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			database.Close()
			sqliteDB.Close()
		})

		Context("with a single host", func() {
			BeforeEach(func() {
				var err error
				certExpiration, err = time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
				Expect(err).NotTo(HaveOccurred())

				host = scanner.ScanResult{
					IP:  "10.0.0.1",
					Job: "custom_name/0",
					Services: []scantron.Process{{
						CommandName: "server-name",
						PID:         213,
						User:        "root",
						Cmdline:     []string{"this", "is", "a", "cmd"},
						Env:         []string{"PATH=this", "OTHER=that"},
						Ports: []scantron.Port{
							{
								Protocol: "TCP",
								Address:  "123.0.0.1",
								Number:   123,
								TLSInformation: scantron.TLSInformation{
									ScanError: errors.New("this was a terrible error"),
									CipherInformation: tlsscan.CipherSuiteResults{
										"tls1.0": []string{
											"ECDHE-NOT-REALLY-SECURE",
										},
										"tls1.1": []string{
											"ECDHE-REALLY-SECURE",
										},
									},
									Certificate: &scantron.Certificate{
										Expiration: certExpiration,
										Bits:       234,
										Subject: scantron.CertificateSubject{
											Country:      "some-country",
											Province:     "some-province",
											Locality:     "some-locality",
											Organization: "some-organization",
											CommonName:   "some-common-name",
										},
									},
								},
							},
						},
					}},
					Files: []scantron.File{
						{
							Path:        "some-file-path",
							Permissions: 0644,
						},
					},
				}

				hosts = []scanner.ScanResult{host}
			})

			It("records a process", func() {
				rows, err := sqliteDB.Query(`
				SELECT hosts.name,
							 hosts.ip,
							 processes.pid,
							 processes.user,
							 processes.cmdline,
							 ports.protocol,
							 ports.address,
							 ports.number,
							 tls_informations.cert_expiration,
							 tls_informations.cert_bits,
							 tls_informations.cert_country,
							 tls_informations.cert_province,
							 tls_informations.cert_locality,
							 tls_informations.cert_organization,
							 tls_informations.cert_common_name,
							 tls_informations.cipher_suites,
							 tls_scan_errors.cert_scan_error,
							 env_vars.var,
							 files.path,
							 files.permissions
				FROM   hosts,
							 processes,
							 ports,
							 tls_informations,
							 tls_scan_errors,
							 env_vars,
							 files
				WHERE  hosts.id = processes.host_id
							 AND ports.process_id = processes.id
							 AND ports.id = tls_informations.port_id
							 AND ports.id = tls_scan_errors.port_id
							 AND files.host_id = hosts.id
						   AND env_vars.process_id=processes.id`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()

				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					name, ip, user, cmdline, env, portProtocol, portAddress string
					pid, portNumber                                         int

					tlsCertCountry,
					tlsCertProvince,
					tlsCertLocality,
					tlsCertOrganization,
					tlsCertCommonName string
					tlsCertBits     int
					tlsCertExp      time.Time
					certScanError   string
					filePath        string
					cipherSuites    string
					filePermissions os.FileMode
				)

				err = rows.Scan(&name, &ip, &pid, &user, &cmdline, &portProtocol,
					&portAddress, &portNumber, &tlsCertExp, &tlsCertBits,
					&tlsCertCountry, &tlsCertProvince, &tlsCertLocality,
					&tlsCertOrganization, &tlsCertCommonName, &cipherSuites, &certScanError, &env, &filePath, &filePermissions)
				Expect(err).NotTo(HaveOccurred())

				Expect(name).To(Equal("custom_name/0"))
				Expect(ip).To(Equal("10.0.0.1"))
				Expect(pid).To(Equal(213))
				Expect(user).To(Equal("root"))
				Expect(portAddress).To(Equal("123.0.0.1"))
				Expect(portNumber).To(Equal(123))
				Expect(tlsCertExp.Equal(certExpiration)).To(BeTrue())
				Expect(tlsCertBits).To(Equal(234))
				Expect(tlsCertCountry).To(Equal("some-country"))
				Expect(tlsCertProvince).To(Equal("some-province"))
				Expect(tlsCertLocality).To(Equal("some-locality"))
				Expect(tlsCertOrganization).To(Equal("some-organization"))
				Expect(tlsCertCommonName).To(Equal("some-common-name"))
				Expect(cipherSuites).To(MatchJSON(`{"tls1.0": ["ECDHE-NOT-REALLY-SECURE"], "tls1.1": ["ECDHE-REALLY-SECURE"]}`))
				Expect(certScanError).To(Equal("this was a terrible error"))
				Expect(cmdline).To(Equal("this is a cmd"))
				Expect(env).To(Equal("PATH=this OTHER=that"))
				Expect(filePath).To(Equal("some-file-path"))
				Expect(filePermissions).To(Equal(os.FileMode(0644)))
			})

			Context("when the service does not have a certificate", func() {
				BeforeEach(func() {
					service := host.Services[0]
					service.Ports[0].TLSInformation.Certificate = nil

					host.Services[0] = service
				})

				It("records a process", func() {
					rows, err := sqliteDB.Query(`
						SELECT hosts.NAME,
									 hosts.ip,
									 processes.pid,
									 processes.USER,
									 ports.protocol,
									 ports.address,
									 ports.number
						FROM   hosts,
									 processes,
									 ports
						WHERE  hosts.id = processes.host_id
									 AND ports.process_id = processes.id`)

					Expect(err).NotTo(HaveOccurred())
					defer rows.Close()

					hasRows := rows.Next()
					Expect(hasRows).To(BeTrue())

					var (
						name, ip, user, portProtocol, portAddress string
						pid, portNumber                           int
					)

					err = rows.Scan(&name, &ip, &pid, &user, &portProtocol, &portAddress, &portNumber)
					Expect(err).NotTo(HaveOccurred())

					Expect(name).To(Equal("custom_name/0"))
					Expect(ip).To(Equal("10.0.0.1"))
					Expect(pid).To(Equal(213))
					Expect(user).To(Equal("root"))
					Expect(portProtocol).To(Equal("TCP"))
					Expect(portAddress).To(Equal("123.0.0.1"))
					Expect(portNumber).To(Equal(123))
				})

				It("does not store any tls information", func() {
					rows, err := sqliteDB.Query(`SELECT count(1) FROM tls_informations`)
					Expect(err).NotTo(HaveOccurred())
					defer rows.Close()

					hasRows := rows.Next()
					Expect(hasRows).To(BeTrue())

					var count int
					err = rows.Scan(&count)
					Expect(err).NotTo(HaveOccurred())

					Expect(count).To(BeZero())
				})
			})

			It("belongs to a report", func() {
				saveTime := time.Now()

				rows, err := sqliteDB.Query(`
				SELECT reports.id,
				       reports.timestamp,
				       hosts.name,
				       hosts.ip
				FROM   hosts,
							 reports
				WHERE  hosts.report_id = reports.id`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()

				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var reportId, name, ip string
				var reportTime time.Time

				err = rows.Scan(&reportId, &reportTime, &name, &ip)
				Expect(err).NotTo(HaveOccurred())

				Expect(reportId).To(Equal("1"))
				Expect(reportTime).Should(BeTemporally("~", saveTime.UTC(), time.Second))
				Expect(name).To(Equal("custom_name/0"))
				Expect(ip).To(Equal("10.0.0.1"))
			})
		})

		Context("with a multiple services that have the same host and job", func() {
			BeforeEach(func() {
				hosts = []scanner.ScanResult{
					{
						IP:  "10.0.0.1",
						Job: "custom_name/0",
					},
					{
						IP:  "10.0.0.1",
						Job: "custom_name/0",
					},
				}
			})

			It("records only a single host", func() {
				rows, err := sqliteDB.Query(`SELECT COUNT(*) FROM hosts`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()

				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var count int
				err = rows.Scan(&count)
				Expect(err).NotTo(HaveOccurred())

				Expect(count).To(Equal(1))
			})
		})

		Context("with a multiple services on different hosts", func() {
			BeforeEach(func() {
				hosts = []scanner.ScanResult{
					{
						IP:  "10.0.0.1",
						Job: "custom_name/0",
					},
					{
						IP:  "10.0.0.2",
						Job: "custom_name/0",
					},
				}
			})

			It("records both hosts", func() {
				rows, err := sqliteDB.Query(`SELECT COUNT(*) FROM hosts`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()

				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var count int
				err = rows.Scan(&count)
				Expect(err).NotTo(HaveOccurred())

				Expect(count).To(Equal(2))
			})
		})
	})
})
