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
		URL          string   `long:"director-url" description:"BOSH Director URL" value-name:"URL" required:"true"`
		Deployments  []string `long:"bosh-deployment" description:"BOSH Deployment" value-name:"DEPLOYMENT_NAME" required:"true"`
		CACert       string   `long:"ca-cert" description:"Director CA certificate path" value-name:"CA_CERT"`
		Client       string   `long:"client" description:"Username or UAA client" value-name:"CLIENT"`
		ClientSecret string   `long:"client-secret" description:"Password or UAA client secret" value-name:"CLIENT_SECRET"`
	} `group:"Director & Deployment"`

	FileRegexes scantron.FileMatch `group:"File Content Check"`
	Database    string             `long:"database" description:"location of database where scan output will be stored" value-name:"PATH" default:"./database.db"`
	Serial      bool               `long:"serial" description:"run scans serially"`
}

type ScanResult struct {
	name  string
	value scanner.ScanResult
}

func scan(dep bosh.TargetDeployment, command *BoshScanCommand, logger scanlog.Logger, results chan<- ScanResult) {
	result, err := scanner.Bosh(dep).Scan(&command.FileRegexes, logger)
	if err != nil {
		log.Fatalf("failed to scan: %s", err.Error())
	}

	results <- ScanResult{dep.Name(), result}
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

	noOfDeployments := len(deployments)
	wg := &sync.WaitGroup{}
	wg.Add(noOfDeployments)

	results := make(chan ScanResult, noOfDeployments)
	quit := make(chan bool)

	// Inform that it is time to quit after enough writes
	go func() {
		wg.Wait()
		db.Close()
		quit <- true
	}()

	// Scan all deployments
	for _, d := range deployments {
		if command.Serial {
			scan(d, command, logger, results)
		} else {
			go scan(d, command, logger, results)
		}
	}

	for {
		select {
		case result := <-results:
			err = db.SaveReport(result.name, result.value)

			if err != nil {
				log.Fatalf("failed to save to database: %s", err.Error())
			}
			wg.Done()
		case <-quit:
			close(results)
			close(quit)

			fmt.Println("Report is saved in SQLite3 database:", command.Database)

			return nil
		}
	}
}
