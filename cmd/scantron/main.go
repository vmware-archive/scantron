package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"

	"github.com/cloudfoundry-incubator/candiedyaml"
	"github.com/jessevdk/go-flags"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanner"
	"github.com/pivotal-golang/lager"

	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	nmap "github.com/lair-framework/go-nmap"
)

type Opts struct {
	NmapResults string `long:"nmap-results" description:"Path to nmap results XML" value-name:"PATH" required:"true"`
	Inventory   string `long:"inventory" description:"Path to inventory XML" value-name:"PATH"`

	BOSH struct {
		URL        string `long:"director-url" description:"BOSH Director URL" value-name:"URL"`
		Username   string `long:"director-username" description:"BOSH Director username" value-name:"USERNAME"`
		Password   string `long:"director-password" description:"BOSH Director password" value-name:"PASSWORD"`
		Deployment string `long:"bosh-deployment" description:"BOSH Deployment" value-name:"DEPLOYMENT_NAME"`
	}

	Gateway struct {
		Username       string `long:"gateway-username" description:"BOSH VM gateway username" value-name:"USERNAME"`
		Host           string `long:"gateway-host" description:"BOSH VM gateway host" value-name:"URL"`
		PrivateKeyPath string `long:"gateway-private-key" description:"BOSH VM gateway private key" value-name:"PATH"`
	}

	UAA struct {
		Client       string `long:"uaa-client" description:"UAA Client" value-name:"OAUTH_CLIENT"`
		ClientSecret string `long:"uaa-client-secret" description:"UAA Client Secret" value-name:"OAUTH_CLIENT_SECRET"`
	}
}

func main() {
	var opts Opts

	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		log.Fatalf(err.Error())
	}

	f, err := os.Open(opts.NmapResults)
	if err != nil {
		log.Fatalf("failed to open nmap results: %s", err.Error())
	}
	defer f.Close()

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatalf("failed to read nmap results: %s", err.Error())
	}

	nmapRun, err := nmap.Parse(bs)
	if err != nil {
		log.Fatalf("failed to parse nmap results: %s", err.Error())
	}

	logger := lager.NewLogger("scantron")
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.DEBUG))

	var s scanner.Scanner

	if opts.BOSH.URL != "" {
		out := bufio.NewWriter(os.Stdout)
		boshLogger := boshlog.NewWriterLogger(boshlog.LevelNone, out, nil)

		s = scanner.Bosh(
			nmapRun,
			opts.BOSH.Deployment,
			opts.BOSH.URL,
			opts.BOSH.Username,
			opts.BOSH.Password,
			boshLogger,
			opts.UAA.Client,
			opts.UAA.ClientSecret,
			opts.Gateway.Username,
			opts.Gateway.Host,
			opts.Gateway.PrivateKeyPath,
		)
	} else {
		inventory := &scantron.Inventory{}
		f, err = os.Open(opts.Inventory)
		if err != nil {
			log.Fatalf("failed to open inventory: %s", err.Error())
		}
		defer f.Close()

		decoder := candiedyaml.NewDecoder(f)
		err = decoder.Decode(&inventory)
		if err != nil {
			log.Fatalf("failed to parse inventory", err.Error())
		}

		s = scanner.Direct(nmapRun, inventory)
	}

	err = s.Scan(logger)
	if err != nil {
		log.Fatalf("failed to scan: %s", err.Error())
	}
}
