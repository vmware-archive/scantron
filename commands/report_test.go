package commands_test

import (
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/scanner"
)

var _ = Describe("Report", func() {
	var (
		databasePath string
	)

	BeforeEach(func() {
		hosts := []scanner.ScanResult{
			{
				Job: "host3",
				Services: []scantron.Process{
					{
						CommandName: "command1",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.23",
								Number:  7890,
							},
						},
					},
				},
			},
			{
				Job: "host1",
				Services: []scantron.Process{
					{
						CommandName: "command2",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.21",
								Number:  9999,
							},
						},
					},
					{
						CommandName: "command1",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.21",
								Number:  7890,
							},
							{
								State:   "LISTEN",
								Address: "44.44.44.44",
								Number:  7890,
							},
							{
								State:   "LISTEN",
								Address: "127.0.0.1",
								Number:  8890,
							},
							{
								State:  "ESTABLISHED",
								Number: 7891,
							},
						},
					},
					{
						CommandName: "sshd",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.21",
								Number:  22,
							},
						},
					},
					{
						CommandName: "rpcbind",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.21",
								Number:  111,
							},
						},
					},
				},
			},
			{
				Job: "host2",
				Services: []scantron.Process{
					{
						CommandName: "command2",
						User:        "root",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.22",
								Number:  9999,
							},
						},
					},
					{
						CommandName: "some-non-root-process",
						User:        "vcap",
						Ports: []scantron.Port{
							{
								State:   "LISTEN",
								Address: "10.0.5.22",
								Number:  12345,
							},
						},
					},
				},
			},
		}

		databaseFile, err := ioutil.TempFile("", "database.db")
		Expect(err).NotTo(HaveOccurred())
		databaseFile.Close()

		databasePath = databaseFile.Name()

		database, err := db.CreateDatabase(databasePath)
		Expect(err).NotTo(HaveOccurred())

		err = database.SaveReport(hosts)
		Expect(err).NotTo(HaveOccurred())

		err = database.Close()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := os.Remove(databasePath)
		Expect(err).NotTo(HaveOccurred())
	})

	It("shows the process running as root user which is listening on an external port", func() {
		session := runCommand("report", "--database", databasePath)

		Expect(session).To(Exit(0))

		Expect(session.Out).To(Say("Processes Running as Root:"))
		Expect(session.Out).To(Say(`\|\s+HOSTNAME\s+\|\s+PORT\s+\|\s+PROCESS NAME\s+\|`))

		Expect(session.Out).To(Say(`\|\s+host1\s+\|\s+7890\s+\|\s+command1\s+\|`))
		Expect(session.Out).To(Say(`\|\s+host1\s+\|\s+9999\s+\|\s+command2\s+\|`))
		Expect(session.Out).To(Say(`\|\s+host2\s+\|\s+9999\s+\|\s+command2\s+\|`))
		Expect(session.Out).To(Say(`\|\s+host3\s+\|\s+7890\s+\|\s+command1\s+\|`))

		contents := session.Out.Contents()

		Expect(contents).NotTo(ContainSubstring("7891"))                  // ignore processes not in LISTEN state
		Expect(contents).NotTo(ContainSubstring("8890"))                  // ignore processes listening on 127.0.0.1
		Expect(contents).NotTo(ContainSubstring("some-non-root-process")) // ignore processes not running as root
		Expect(contents).NotTo(ContainSubstring("sshd"))                  // ignore sshd process
		Expect(contents).NotTo(ContainSubstring("rpcbind"))               // ignore rpcbind process
	})
})
