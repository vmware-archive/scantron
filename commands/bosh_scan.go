package commands

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"code.cloudfoundry.org/lager"
	boshconfig "github.com/cloudfoundry/bosh-cli/cmd/config"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	nmap "github.com/lair-framework/go-nmap"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/remotemachine"
	"github.com/pivotal-cf/scantron/scanner"
)

type BoshScanCommand struct {
	NmapResults string `long:"nmap-results" description:"Path to nmap results XML" value-name:"PATH" required:"true"`

	Director struct {
		URL        string `long:"director-url" description:"BOSH Director URL" value-name:"URL" required:"true"`
		Deployment string `long:"bosh-deployment" description:"BOSH Deployment" value-name:"DEPLOYMENT_NAME" required:"true"`

		CACert string `long:"ca-cert" description:"Director CA certificate path" value-name:"CA_CERT"`

		Client       string `long:"client" description:"Username or UAA client" value-name:"CLIENT"`
		ClientSecret string `long:"client-secret" description:"Password or UAA client secret" value-name:"CLIENT_SECRET"`
	} `group:"Director & Deployment"`

	Gateway struct {
		Username       string `long:"gateway-username" description:"BOSH VM gateway username" value-name:"USERNAME"`
		Host           string `long:"gateway-host" description:"BOSH VM gateway host" value-name:"URL"`
		PrivateKeyPath string `long:"gateway-private-key" description:"BOSH VM gateway private key" value-name:"PATH"`
	} `group:"Gateway"`

	Database string `long:"database" description:"location of database where scan output will be stored" value-name:"PATH" default:"./database.db"`
}

func (command *BoshScanCommand) Execute(args []string) error {
	logger := lager.NewLogger("scantron")
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.DEBUG))

	out := bufio.NewWriter(os.Stdout)
	boshLogger := boshlog.NewWriterLogger(boshlog.LevelNone, out, nil)

	bs, err := ioutil.ReadFile(command.NmapResults)
	if err != nil {
		log.Fatalf("failed to open nmap results: %s", err.Error())
	}

	nmapRun, err := nmap.Parse(bs)
	if err != nil {
		log.Fatalf("failed to parse nmap results: %s", err.Error())
	}
	nmapResults := scantron.BuildNmapResults(nmapRun)

	director, err := remotemachine.NewBoshDirector(
		logger,
		boshconfig.Creds{
			Client:       command.Director.Client,
			ClientSecret: command.Director.ClientSecret,
		},
		command.Director.CACert,
		command.Director.Deployment,
		command.Director.URL,
		boshLogger,
		command.Gateway.Username,
		command.Gateway.Host,
		command.Gateway.PrivateKeyPath,
	)
	if err != nil {
		log.Fatalf("failed to set up director: %s", err.Error())
	}
	defer director.Cleanup()

	s := scanner.AnnotateWithTLSInformation(
		scanner.Bosh(director),
		nmapResults,
	)

	db, err := OpenOrCreateDatabase(command.Database)

	if err != nil {
		log.Fatalf("failed to create database: %s", err.Error())
	}

	results, err := s.Scan(logger)
	if err != nil {
		log.Fatalf("failed to scan: %s", err.Error())
	}

	err = db.SaveReport(results)
	if err != nil {
		log.Fatalf("failed to save to database: %s", err.Error())
	}

	db.Close()

	fmt.Println("Report is saved in SQLite3 database:", command.Database)

	return nil
}
