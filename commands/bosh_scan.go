package commands

import (
	"fmt"
	boshconfig "github.com/cloudfoundry/bosh-cli/cmd/config"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/bosh"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/scanner"
	"log"
	"sync"
)

type BoshScanCommand struct {
	Director struct {
		URL         string   `long:"director-url" description:"BOSH Director URL" value-name:"URL" required:"true"`
		Deployments []string `long:"bosh-deployment" description:"BOSH Deployment" value-name:"DEPLOYMENT_NAME" required:"true"`

		CACert string `long:"ca-cert" description:"Director CA certificate path" value-name:"CA_CERT"`

		Client       string `long:"client" description:"Username or UAA client" value-name:"CLIENT"`
		ClientSecret string `long:"client-secret" description:"Password or UAA client secret" value-name:"CLIENT_SECRET"`
	} `group:"Director & Deployment"`

	FileRegexes scantron.FileMatch `group:"File Content Check"`

	Database string `long:"database" description:"location of database where scan output will be stored" value-name:"PATH" default:"./database.db"`
}

func (command *BoshScanCommand) Execute(args []string) error {
	scantron.SetDebug(Scantron.Debug)
	logger, err := scanlog.NewLogger(Scantron.Debug)
	if err != nil {
		log.Fatalln("failed to set up logger:", err)
	}

	logger.Debugf("Requested deployments to scan: %v", command.Director.Deployments)

	deployments, err := bosh.GetDeployments(
		boshconfig.Creds{
			Client:       command.Director.Client,
			ClientSecret: command.Director.ClientSecret,
		},
		command.Director.CACert,
		command.Director.Deployments,
		command.Director.URL,
		logger,
	)

	if err != nil {
		log.Fatalf("failed to set up director: %s", err.Error())
	}

	db, err := db.CreateDatabase(command.Database)
	if err != nil {
		log.Fatalf("failed to create database: %s", err.Error())
	}

	m := sync.Mutex{}
	wg := &sync.WaitGroup{}
	wg.Add(len(deployments))
	for _, d := range deployments {
		logger.Debugf("About to launch go func: %s", d.Name())
		go func(dep bosh.TargetDeployment) {
			defer wg.Done()

			logger.Debugf("About to scan: %s", dep.Name())
			results, err := scanner.Bosh(dep).Scan(&command.FileRegexes, logger)
			if err != nil {
				log.Fatalf("failed to scan: %s", err.Error())
			}

			m.Lock()
			defer m.Unlock()
			err = db.SaveReport(dep.Name(), results)
			if err != nil {
				log.Fatalf("failed to save to database: %s", err.Error())
			}
		}(d)
	}

	wg.Wait()

	db.Close()

	fmt.Println("Report is saved in SQLite3 database:", command.Database)

	return nil
}
