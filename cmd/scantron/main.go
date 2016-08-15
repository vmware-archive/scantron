package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/cloudfoundry-incubator/candiedyaml"
	"github.com/jessevdk/go-flags"
	"github.com/lair-framework/go-nmap"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"
)

type Opts struct {
	NmapResults string `long:"nmap-results" description:"path to XML nmap results file" value-name:"FILE" required:"true"`
	Inventory   string `long:"inventory" description:"path to an inventory file" required:"true"`
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

	f, err = os.Open(opts.Inventory)
	if err != nil {
		log.Fatalf("failed to open inventory: %s", err.Error())
	}
	defer f.Close()

	inventory := new(scantron.Inventory)
	decoder := candiedyaml.NewDecoder(f)
	err = decoder.Decode(&inventory)
	if err != nil {
		log.Fatalf("failed to parse inventory", err.Error())
	}

	logger := lager.NewLogger("scantron")
	logger.RegisterSink(lager.NewWriterSink(os.Stderr, lager.INFO))

	scantron.Scan(logger, nmapRun, inventory)
}
