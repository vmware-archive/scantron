package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"text/tabwriter"

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

const asciiCross = "\u2717"
const asciiCheckmark = "\u2713"

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
	nmapResults := scantron.BuildNmapResults(nmapRun)

	logger := lager.NewLogger("scantron")
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.DEBUG))

	var s scanner.Scanner

	if opts.BOSH.URL != "" {
		out := bufio.NewWriter(os.Stdout)
		boshLogger := boshlog.NewWriterLogger(boshlog.LevelNone, out, nil)

		s = scanner.Bosh(
			nmapResults,
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

		s = scanner.Direct(nmapResults, inventory)
	}

	results, err := s.Scan(logger)
	if err != nil {
		log.Fatalf("failed to scan: %s", err.Error())
	}

	wr := tabwriter.NewWriter(os.Stdout, 0, 8, 0, '\t', 0)

	fmt.Fprintln(wr, strings.Join([]string{"IP Address", "Job", "Service", "Port", "User", "SSL"}, "\t"))

	for _, result := range results {
		ssl := asciiCross
		if result.SSL {
			ssl = asciiCheckmark
		}

		fmt.Fprintln(wr, fmt.Sprintf("%s\t%s\t%s\t%d\t%s\t%s", result.IP, result.Hostname, result.Name, result.Port, result.User, ssl))
	}

	err = wr.Flush()
	if err != nil {
		log.Fatalf("failed to flush tabwriter", err)
	}
}
