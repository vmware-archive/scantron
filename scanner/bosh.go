package scanner

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"

	boshcmd "github.com/cloudfoundry/bosh-init/cmd"
	boshconfig "github.com/cloudfoundry/bosh-init/cmd/config"
	boshdir "github.com/cloudfoundry/bosh-init/director"
	boshssh "github.com/cloudfoundry/bosh-init/ssh"
	boshuaa "github.com/cloudfoundry/bosh-init/uaa"
	boshui "github.com/cloudfoundry/bosh-init/ui"
	nmap "github.com/lair-framework/go-nmap"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-golang/lager"

	boshlog "github.com/cloudfoundry/bosh-utils/logger"
)

type boshScanner struct {
	nmapRun               *nmap.NmapRun
	creds                 boshconfig.Creds
	deploymentName        string
	boshURL               string
	boshUsername          string
	boshPassword          string
	boshLogger            boshlog.Logger
	gatewayUsername       string
	gatewayHost           string
	gatewayPrivateKeyPath string
}

func Bosh(
	nmapRun *nmap.NmapRun,
	deploymentName string,
	boshURL string,
	boshUsername string,
	boshPassword string,
	boshLogger boshlog.Logger,
	uaaClient string,
	uaaClientSecret string,
	gatewayUsername string,
	gatewayHost string,
	gatewayPrivateKeyPath string,
) Scanner {
	return &boshScanner{
		nmapRun: nmapRun,
		creds: boshconfig.Creds{
			Client:       uaaClient,
			ClientSecret: uaaClientSecret,
		},

		deploymentName: deploymentName,

		boshURL:      boshURL,
		boshUsername: boshUsername,
		boshPassword: boshPassword,
		boshLogger:   boshLogger,

		gatewayUsername:       gatewayUsername,
		gatewayHost:           gatewayHost,
		gatewayPrivateKeyPath: gatewayPrivateKeyPath,
	}
}

func (s *boshScanner) Scan(logger lager.Logger) ([]ScannedService, error) {
	director, err := getDirector(s.boshURL, s.boshUsername, s.boshPassword, s.creds, s.boshLogger)
	if err != nil {
		logger.Error("failed-to-get-director", err)
		return nil, err
	}

	deployment, err := director.FindDeployment(s.deploymentName)
	if err != nil {
		logger.Error("failed-to-find-deployment", err)
		return nil, err
	}

	vmInfos, err := deployment.VMInfos()
	if err != nil {
		logger.Error("failed-to-get-vm-infos", err)
		return nil, err
	}

	inventory := &scantron.Inventory{}

	for _, vmInfo := range vmInfos {
		inventory.Hosts = append(inventory.Hosts, scantron.Host{
			Name:      fmt.Sprintf("%s/%d", vmInfo.JobName, *vmInfo.Index),
			Addresses: vmInfo.IPs,
		})
	}

	ui := boshui.NewConfUI(s.boshLogger)
	ui.EnableJSON()
	defer ui.Flush()

	deps := boshcmd.NewBasicDeps(ui, s.boshLogger)

	tmpDir, err := ioutil.TempDir("", "scantron")
	if err != nil {
		logger.Error("failed-to-create-temp-dir", err)
		return nil, err
	}

	tmpDirPath, err := deps.FS.ExpandPath(tmpDir)
	if err != nil {
		logger.Error("failed-to-expand-temp-dir-path", err)
		return nil, err
	}
	defer os.RemoveAll(tmpDirPath)

	err = deps.FS.ChangeTempRoot(tmpDirPath)
	if err != nil {
		logger.Error("failed-to-change-temp-root", err)
		return nil, err
	}

	sshSessionFactory := func(o boshssh.ConnectionOpts, r boshdir.SSHResult) boshssh.Session {
		return boshssh.NewSessionImpl(o, boshssh.SessionImplOpts{ForceTTY: true}, r, deps.FS)
	}

	sshWriter := NewMemWriter()

	sshRunner := boshssh.NewNonInteractiveRunner(
		boshssh.NewComboRunner(
			deps.CmdRunner,
			sshSessionFactory,
			signal.Notify,
			sshWriter,
			deps.FS,
			ui,
			s.boshLogger,
		),
	)

	sshOpts, privKey, err := boshdir.NewSSHOpts(deps.UUIDGen)
	if err != nil {
		logger.Error("failed-to-create-ssh-opts", err)
		return nil, err
	}

	var scannedServices []ScannedService

	for _, vmInfo := range vmInfos {
		fmt.Printf("Scanning %s/%s... ", vmInfo.JobName, vmInfo.ID)

		slug := boshdir.NewAllOrPoolOrInstanceSlug(vmInfo.JobName, vmInfo.ID)
		sshResult, err := deployment.SetUpSSH(slug, sshOpts)
		if err != nil {
			fmt.Printf("ERROR\n")
			logger.Error("failed-to-set-up-ssh", err)
			return nil, err
		}
		defer deployment.CleanUpSSH(slug, sshOpts)

		connOpts := boshssh.ConnectionOpts{
			PrivateKey: privKey,

			GatewayUsername:       s.gatewayUsername,
			GatewayHost:           s.gatewayHost,
			GatewayPrivateKeyPath: s.gatewayPrivateKeyPath,
		}

		cmd := "sudo lsof -iTCP -sTCP:LISTEN +c0 -FcnL -P -n"
		err = sshRunner.Run(connOpts, sshResult, strings.Split(cmd, " "))
		if err != nil {
			fmt.Printf("ERROR\n")
			logger.Error("failed-to-run-cmd", err)
			return nil, err
		}

		for _, nmapHost := range s.nmapRun.Hosts {
			if nmapHost.Addresses[0].Addr != vmInfo.IPs[0] {
				continue
			}

			result := sshWriter.ResultsForHost(nmapHost.Addresses[0].Addr)
			if result != nil {
				processes := ParseLSOFOutput(result.StdoutString())
				for _, nmapPort := range nmapHost.Ports {
					for _, process := range processes {
						if process.HasFileWithPort(nmapPort.PortId) {
							scannedServices = append(scannedServices, ScannedService{
								Hostname: vmInfo.JobName,
								IP:       vmInfo.IPs[0],
								Name:     process.CommandName,
								User:     process.User,
								Port:     nmapPort.PortId,
								SSL:      len(nmapPort.Service.Tunnel) > 0,
							})
						}
					}
				}
			}
		}

		fmt.Printf("DONE\n")
	}

	return scannedServices, nil
}

func getDirector(
	boshURL string,
	boshUsername string,
	boshPassword string,
	creds boshconfig.Creds,
	logger boshlog.Logger,
) (boshdir.Director, error) {
	dirConfig, err := boshdir.NewConfigFromURL(boshURL)
	if err != nil {
		return nil, err
	}

	uaa, err := getUAA(dirConfig, creds, logger)
	if err != nil {
		return nil, err
	}

	if creds.IsUAAClient() {
		dirConfig.TokenFunc = boshuaa.NewClientTokenSession(uaa).TokenFunc
	} else {
		dirConfig.Username = boshUsername
		dirConfig.Password = boshPassword
	}

	director, err := boshdir.NewFactory(logger).New(dirConfig, boshdir.NewNoopTaskReporter(), boshdir.NewNoopFileReporter())
	if err != nil {
		return nil, err
	}

	return director, nil
}

func getUAA(dirConfig boshdir.Config, creds boshconfig.Creds, logger boshlog.Logger) (boshuaa.UAA, error) {
	director, err := boshdir.NewFactory(logger).New(dirConfig, boshdir.NewNoopTaskReporter(), boshdir.NewNoopFileReporter())
	if err != nil {
		return nil, err
	}

	info, err := director.Info()
	if err != nil {
		return nil, err
	}

	uaaURL := info.Auth.Options["url"]

	uaaURLStr, ok := uaaURL.(string)
	if !ok {
		return nil, err
	}

	uaaConfig, err := boshuaa.NewConfigFromURL(uaaURLStr)
	if err != nil {
		return nil, err
	}

	uaaConfig.Client = creds.Client
	uaaConfig.ClientSecret = creds.ClientSecret

	return boshuaa.NewFactory(logger).New(uaaConfig)
}
