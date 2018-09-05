package commands

import (
	"bufio"
	"fmt"
	"log"
	"os"

	boshconfig "github.com/cloudfoundry/bosh-cli/cmd/config"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"

	"github.com/pivotal-cf/scantron/bosh"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/scanner"
)

type BoshScanCommand struct {
	Director struct {
		URL        string `long:"director-url" description:"BOSH Director URL" value-name:"URL" required:"true"`
		Deployment string `long:"bosh-deployment" description:"BOSH Deployment" value-name:"DEPLOYMENT_NAME" required:"true"` // TODO multiple deployments

		CACert string `long:"ca-cert" description:"Director CA certificate path" value-name:"CA_CERT"`

		Client       string `long:"client" description:"Username or UAA client" value-name:"CLIENT"`
		ClientSecret string `long:"client-secret" description:"Password or UAA client secret" value-name:"CLIENT_SECRET"`
	} `group:"Director & Deployment"`

	Database string `long:"database" description:"location of database where scan output will be stored" value-name:"PATH" default:"./database.db"`
}

func (command *BoshScanCommand) Execute(args []string) error {
	logger, err := scanlog.NewLogger(Scantron.Debug)
	if err != nil {
		log.Fatalln("failed to set up logger:", err)
	}

	out := bufio.NewWriter(os.Stdout)
	boshLogger := boshlog.NewWriterLogger(boshlog.LevelNone, out)

	director, err := bosh.NewBoshDirector(
		logger,
		boshconfig.Creds{
			Client:       command.Director.Client,
			ClientSecret: command.Director.ClientSecret,
		},
		command.Director.CACert,
		command.Director.Deployment,
		command.Director.URL,
		boshLogger,
	)
	if err != nil {
		log.Fatalf("failed to set up director: %s", err.Error())
	}
	defer director.Cleanup()

	db, err := db.CreateDatabase(command.Database)
	if err != nil {
		log.Fatalf("failed to create database: %s", err.Error())
	}

	results, err := scanner.Bosh(director).Scan(logger)
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
