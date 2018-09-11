package commands

import (
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/ssh"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/db"
	"github.com/pivotal-cf/scantron/remotemachine"
	"github.com/pivotal-cf/scantron/scanlog"
	"github.com/pivotal-cf/scantron/scanner"
)

type DirectScanCommand struct {
	Address    string `long:"address" description:"Address of machine to scan" value-name:"ADDRESS" required:"true"`
	Username   string `long:"username" description:"Username of machine to scan" value-name:"USERNAME" required:"true"`
	Password   string `long:"password" description:"Password of machine to scan" value-name:"PASSWORD" required:"true"`
	PrivateKey string `long:"private-key" description:"Private key of machine to scan" value-name:"PATH"`
	Database   string `long:"database" description:"location of database where scan output will be stored" value-name:"PATH" default:"./database.db"`
	OSName     string `long:"os-name" description:"Name of stemcell OS of machine to scan" value-name:"STRING" required:"true"`
}

func (command *DirectScanCommand) Execute(args []string) error {
	scantron.SetDebug(Scantron.Debug)
	logger, err := scanlog.NewLogger(Scantron.Debug)
	if err != nil {
		log.Fatalln("failed to set up logger:", err)
	}

	var privateKey ssh.Signer

	if command.PrivateKey != "" {
		key, err := ioutil.ReadFile(command.PrivateKey)
		if err != nil {
			log.Fatalf("unable to read private key: %s", err.Error())
		}

		privateKey, err = ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("unable to parse private key: %s", err.Error())
		}
	}

	machine := scantron.Machine{
		Address:  command.Address,
		Username: command.Username,
		Password: command.Password,
		Key:      privateKey,
		OSName:   command.OSName,
	}

	remoteMachine := remotemachine.NewRemoteMachine(machine)
	defer remoteMachine.Close()

	db, err := db.CreateDatabase(command.Database)
	if err != nil {
		log.Fatalf("failed to create database: %s", err.Error())
	}

	results, err := scanner.Direct(remoteMachine).Scan(logger)
	if err != nil {
		log.Fatalf("failed to scan: %s", err.Error())
	}

	err = db.SaveReport("direct-scan", results)
	if err != nil {
		log.Fatalf("failed to save to database: %s", err.Error())
	}

	db.Close()

	fmt.Println("Report saved in SQLite3 database:", command.Database)

	return nil
}
