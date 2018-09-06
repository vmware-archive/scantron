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

	Describe("CreateDatabase", func() {
		It("creates a new database file", func() {
			database, err := db.CreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer database.Close()

			Expect(dbPath).To(BeAnExistingFile())
		})

		It("creates the required tables", func() {
			database, err := db.CreateDatabase(dbPath)
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
				"env_vars",
				"files",
				"hosts",
				"ports",
				"processes",
				"releases",
				"ssh_keys",
				"tls_informations",
				"tls_scan_errors",
				"version",
			))
		})

		It("sets the schema version", func() {
			database, err := db.CreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer database.Close()

			Expect(database.Version()).To(Equal(db.SchemaVersion))
		})

		Context("when the database already exists", func() {
			BeforeEach(func() {
				database, err := sql.Open("sqlite3", dbPath)
				Expect(err).NotTo(HaveOccurred())

				// We need to perform a query to create the database file
				_, err = database.Exec("CREATE TABLE test (id integer);")
				Expect(err).NotTo(HaveOccurred())
				defer database.Close()
			})

			It("returns an error", func() {
				_, err := db.CreateDatabase(dbPath)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("OpenDatabase", func() {
		BeforeEach(func() {
			database, err := db.CreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())
			database.Close()
		})

		It("returns a connection to the database", func() {
			database, err := db.OpenDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())

			Expect(database.Version()).To(Equal(db.SchemaVersion))
		})

		It("returns an error when the database does not exist", func() {
			bogusPath := filepath.Join(tmpdir, "i am a bogus database")
			os.RemoveAll(bogusPath)
			_, err := db.OpenDatabase(bogusPath)
			Expect(err).To(HaveOccurred())
			_, err = os.Stat(bogusPath)
			Expect(os.IsNotExist(err)).To(BeTrue())
		})

		It("returns an error when the database version is unknown", func() {
			sqliteDB, err := sql.Open("sqlite3", dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer sqliteDB.Close()

			_, err = sqliteDB.Exec("DROP TABLE version")
			Expect(err).NotTo(HaveOccurred())

			_, err = db.OpenDatabase(dbPath)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("The database version (0) does not match latest version"))
		})

		It("returns an error when the database version is old", func() {
			sqliteDB, err := sql.Open("sqlite3", dbPath)
			Expect(err).NotTo(HaveOccurred())
			defer sqliteDB.Close()

			_, err = sqliteDB.Exec("UPDATE version SET version = -42")
			Expect(err).NotTo(HaveOccurred())

			_, err = db.OpenDatabase(dbPath)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("The database version (-42) does not match latest version"))
		})
	})

	Describe("SaveReport", func() {
		var (
			database       *db.Database
			hosts          scanner.ScanResult
			host           scanner.JobResult
			sqliteDB       *sql.DB
			certExpiration time.Time
		)

		BeforeEach(func() {
			var err error
			database, err = db.CreateDatabase(dbPath)
			Expect(err).NotTo(HaveOccurred())

			sqliteDB, err = sql.Open("sqlite3", dbPath)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			Expect(database.Close()).To(Succeed())
			Expect(sqliteDB.Close()).To(Succeed())
		})

		Context("with a single host", func() {
			BeforeEach(func() {
				var err error
				certExpiration, err = time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
				Expect(err).NotTo(HaveOccurred())

				host = scanner.JobResult{
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
								TLSInformation: &scantron.TLSInformation{
									ScanError: errors.New("this was a terrible error"),
									Mutual:    true,
									CipherInformation: scantron.CipherInformation{
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
					SSHKeys: []scantron.SSHKey{
						{
							Type: "ssh-rsa",
							Key:  "My Special RSA Key",
						},
						{
							Type: "ssh-dss",
							Key:  "My Special DSA Key",
						},
					},
				}

				hosts = scanner.ScanResult{JobResults: []scanner.JobResult{host}}
			})

			It("records host information", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(` SELECT name, ip FROM	hosts `)
				Expect(err).NotTo(HaveOccurred())

				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					name, ip string
				)

				err = rows.Scan(&name, &ip)
				Expect(err).NotTo(HaveOccurred())

				Expect(name).To(Equal("custom_name/0"))
				Expect(ip).To(Equal("10.0.0.1"))
			})

			It("records process information", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(` SELECT pid, user, cmdline FROM processes `)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					pid           int
					user, cmdline string
				)
				err = rows.Scan(&pid, &user, &cmdline)
				Expect(err).NotTo(HaveOccurred())

				Expect(pid).To(Equal(213))
				Expect(user).To(Equal("root"))
				Expect(cmdline).To(Equal("this is a cmd"))
			})

			It("records port information", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(`SELECT protocol, address, number FROM ports`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					protocol, address string
					number            int
				)

				err = rows.Scan(&protocol, &address, &number)
				Expect(err).NotTo(HaveOccurred())

				Expect(protocol).To(Equal("TCP"))
				Expect(address).To(Equal("123.0.0.1"))
				Expect(number).To(Equal(123))
			})

			It("records tls informations", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(`
				SELECT
					cert_expiration,
					cert_bits,
					cert_country,
					cert_province,
					cert_locality,
					cert_organization,
					cert_common_name,
					cipher_suites,
					mutual
				FROM
				  tls_informations`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					cert_expiration                                                                                time.Time
					cert_bits                                                                                      int
					cert_country, cert_province, cert_locality, cert_organization, cert_common_name, cipher_suites string
					mutual                                                                                         bool
				)

				err = rows.Scan(&cert_expiration, &cert_bits, &cert_country, &cert_province, &cert_locality, &cert_organization, &cert_common_name, &cipher_suites, &mutual)
				Expect(err).NotTo(HaveOccurred())

				Expect(cert_expiration.Equal(certExpiration)).To(BeTrue())
				Expect(cert_bits).To(Equal(234))
				Expect(cert_country).To(Equal("some-country"))
				Expect(cert_province).To(Equal("some-province"))
				Expect(cert_locality).To(Equal("some-locality"))
				Expect(cert_organization).To(Equal("some-organization"))
				Expect(cert_common_name).To(Equal("some-common-name"))
				Expect(cipher_suites).To(MatchJSON(`{"tls1.0": ["ECDHE-NOT-REALLY-SECURE"], "tls1.1": ["ECDHE-REALLY-SECURE"]}`))
				Expect(mutual).To(BeTrue())
			})

			It("records tls errors", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(`SELECT cert_scan_error FROM tls_scan_errors`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					cert_scan_error string
				)

				err = rows.Scan(&cert_scan_error)
				Expect(err).NotTo(HaveOccurred())
				Expect(cert_scan_error).To(Equal("this was a terrible error"))
			})

			It("records env_vars info", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(`SELECT env_vars.var FROM env_vars`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var env_vars string

				err = rows.Scan(&env_vars)
				Expect(err).NotTo(HaveOccurred())
				Expect(env_vars).To(Equal("PATH=this OTHER=that"))
			})

			It("records file information", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(`SELECT path, permissions FROM files`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					path        string
					permissions os.FileMode
				)

				err = rows.Scan(&path, &permissions)
				Expect(err).NotTo(HaveOccurred())
				Expect(path).To(Equal("some-file-path"))
				Expect(permissions).To(Equal(os.FileMode(0644)))
			})

			It("records sshkey information", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(`SELECT ssh_keys.type, ssh_keys.key FROM ssh_keys`)
				Expect(err).NotTo(HaveOccurred())
				defer rows.Close()
				hasRows := rows.Next()
				Expect(hasRows).To(BeTrue())

				var (
					sshKeyType, sshKey string
				)

				err = rows.Scan(&sshKeyType, &sshKey)
				Expect(err).NotTo(HaveOccurred())
				Expect(sshKeyType).To(Equal("ssh-rsa"))
				Expect(sshKey).To(Equal("My Special RSA Key"))

				hasRows = rows.Next()
				Expect(hasRows).To(BeTrue())
				err = rows.Scan(&sshKeyType, &sshKey)
				Expect(err).NotTo(HaveOccurred())
				Expect(sshKeyType).To(Equal("ssh-dss"))
				Expect(sshKey).To(Equal("My Special DSA Key"))
			})

			Context("when the service does not have a certificate", func() {
				BeforeEach(func() {
					service := host.Services[0]
					service.Ports[0].TLSInformation.Certificate = nil

					host.Services[0] = service
				})

				It("records a process", func() {
					err := database.SaveReport(hosts)
					Expect(err).NotTo(HaveOccurred())

					rows, err := sqliteDB.Query(`
						SELECT hosts.name,
									 hosts.ip,
									 processes.pid,
									 processes.user,
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
					err := database.SaveReport(hosts)
					Expect(err).NotTo(HaveOccurred())

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
		})

		Context("with a multiple services that have the same host and job", func() {
			BeforeEach(func() {
				hosts = scanner.ScanResult{
					JobResults: []scanner.JobResult{
						{
							IP:  "10.0.0.1",
							Job: "custom_name/0",
						},
						{
							IP:  "10.0.0.1",
							Job: "custom_name/0",
						},
					},
				}
			})

			It("records only a single host", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

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
				hosts = scanner.ScanResult{
					JobResults: []scanner.JobResult{
						{
							IP:  "10.0.0.1",
							Job: "custom_name/0",
						},
						{
							IP:  "10.0.0.2",
							Job: "custom_name/0",
						},
					},
				}
			})

			It("records both hosts", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

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

		Context("with release information", func() {
			BeforeEach(func() {
				hosts.ReleaseResults = []scanner.ReleaseResult{
					{
						Name:    "cf-release",
						Version: "256",
					},
					{
						Name:    "diego-release",
						Version: "2.0.0",
					},
				}
			})

			It("records the release version and name", func() {
				err := database.SaveReport(hosts)
				Expect(err).NotTo(HaveOccurred())

				rows, err := sqliteDB.Query(` SELECT name, version FROM	releases `)
				Expect(err).NotTo(HaveOccurred())

				defer rows.Close()
				Expect(rows.Next()).To(BeTrue())

				var releases []scanner.ReleaseResult

				var name, version string
				err = rows.Scan(&name, &version)
				Expect(err).NotTo(HaveOccurred())
				releases = append(releases, scanner.ReleaseResult{Name: name, Version: version})

				Expect(rows.Next()).To(BeTrue())
				err = rows.Scan(&name, &version)
				Expect(err).NotTo(HaveOccurred())
				releases = append(releases, scanner.ReleaseResult{Name: name, Version: version})

				Expect(releases).To(ConsistOf(hosts.ReleaseResults))
			})

			It("returns an error when inserting fails", func() {
				_, err := sqliteDB.Exec(`DROP TABLE releases`)
				Expect(err).NotTo(HaveOccurred())

				err = database.SaveReport(hosts)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
