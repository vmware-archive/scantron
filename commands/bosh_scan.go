package commands

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"text/tabwriter"

	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	nmap "github.com/lair-framework/go-nmap"
	"github.com/pivotal-golang/lager"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanner"
)

type BoshScanCommand struct {
	NmapResults string `long:"nmap-results" description:"Path to nmap results XML" value-name:"PATH" required:"true"`

	Director struct {
		URL        string `long:"director-url" description:"BOSH Director URL" value-name:"URL" required:"true"`
		Deployment string `long:"bosh-deployment" description:"BOSH Deployment" value-name:"DEPLOYMENT_NAME" required:"true"`

		Username string `long:"director-username" description:"BOSH Director username" value-name:"USERNAME"`
		Password string `long:"director-password" description:"BOSH Director password" value-name:"PASSWORD"`

		Client       string `long:"uaa-client" description:"UAA Client" value-name:"OAUTH_CLIENT"`
		ClientSecret string `long:"uaa-client-secret" description:"UAA Client Secret" value-name:"OAUTH_CLIENT_SECRET"`
	} `group:"Director & Deployment"`

	Gateway struct {
		Username       string `long:"gateway-username" description:"BOSH VM gateway username" value-name:"USERNAME"`
		Host           string `long:"gateway-host" description:"BOSH VM gateway host" value-name:"URL"`
		PrivateKeyPath string `long:"gateway-private-key" description:"BOSH VM gateway private key" value-name:"PATH"`
	} `group:"Gateway"`
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

	s := scanner.Bosh(
		nmapResults,
		command.Director.Deployment,
		command.Director.URL,
		command.Director.Username,
		command.Director.Password,
		boshLogger,
		command.Director.Client,
		command.Director.ClientSecret,
		command.Gateway.Username,
		command.Gateway.Host,
		command.Gateway.PrivateKeyPath,
	)

	results, err := s.Scan(logger)
	if err != nil {
		log.Fatalf("failed to scan: %s", err.Error())
	}

	wr := tabwriter.NewWriter(os.Stdout, 0, 8, 2, '\t', 0)

	fmt.Fprintln(wr, strings.Join([]string{"Host", "Job", "Service", "PID", "Port", "User", "SSL"}, "\t"))

	for _, result := range results {
		ssl := asciiCross
		if result.SSL {
			ssl = asciiCheckmark
		}

		fmt.Fprintln(wr, fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%d\t%s\t%s",
			result.IP,
			result.Hostname,
			result.Name,
			result.PID,
			result.Port,
			result.User,
			ssl),
		)
	}

	err = wr.Flush()
	if err != nil {
		log.Fatalf("failed to flush tabwriter", err)
	}

	return nil
}
