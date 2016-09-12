package commands

import (
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	nmap "github.com/lair-framework/go-nmap"
	"github.com/pivotal-golang/lager"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanner"
)

type DirectScanCommand struct {
	NmapResults string `long:"nmap-results" description:"Path to nmap results XML" value-name:"PATH" required:"true"`

	Address    string `long:"address" description:"Address of machine to scan" value-name:"ADDRESS" required:"true"`
	Username   string `long:"username" description:"Username of machine to scan" value-name:"USERNAME" required:"true"`
	Password   string `long:"password" description:"Password of machine to scan" value-name:"PASSWORD" required:"true"`
	PrivateKey string `long:"private-key" description:"Private key of machine to scan" value-name:"PATH"`
	Database   string `long:"database" description:"location of database where scan output will be stored" value-name:"PATH"`
}

func (command *DirectScanCommand) Execute(args []string) error {
	logger := lager.NewLogger("scantron")
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.DEBUG))

	bs, err := ioutil.ReadFile(command.NmapResults)
	if err != nil {
		log.Fatalf("failed to open nmap results: %s", err.Error())
	}

	nmapRun, err := nmap.Parse(bs)
	if err != nil {
		log.Fatalf("failed to parse nmap results: %s", err.Error())
	}
	nmapResults := scantron.BuildNmapResults(nmapRun)

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

	machine := &scantron.Machine{
		Address:  command.Address,
		Username: command.Username,
		Password: command.Password,
		Key:      privateKey,
	}

	s := scanner.AnnotateWithTLSInformation(
		scanner.Direct(nmapResults, machine),
		nmapResults,
	)

	var db *Database
	if command.Database == "" {
		db, err = NewDatabase("./database.db")
	} else {
		db, err = NewDatabase(command.Database)
	}
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

	err = showReport(results)
	if err != nil {
		log.Fatalf("failed to flush tabwriter %s", err.Error())
	}

	return nil
}
