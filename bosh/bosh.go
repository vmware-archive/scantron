package bosh

import (
	"io/ioutil"
	"net"

	boshconfig "github.com/cloudfoundry/bosh-cli/cmd/config"
	boshdir "github.com/cloudfoundry/bosh-cli/director"
	boshuaa "github.com/cloudfoundry/bosh-cli/uaa"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	boshuuid "github.com/cloudfoundry/bosh-utils/uuid"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/remotemachine"
	"github.com/pivotal-cf/scantron/scanlog"
	"golang.org/x/crypto/ssh"
)

//go:generate counterfeiter . BoshDirector

type BoshDirector interface {
	VMs() []boshdir.VMInfo
	ConnectTo(scanlog.Logger, boshdir.VMInfo) remotemachine.RemoteMachine

	Releases() []boshdir.Release

	Setup() error
	Cleanup() error
}

func NewBoshDirector(
	logger scanlog.Logger,
	creds boshconfig.Creds,
	caCertPath string,
	deploymentName string,
	boshURL string,
	boshLogger boshlog.Logger,
) (BoshDirector, error) {
	var caCert string

	if caCertPath != "" {
		caCertBytes, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			logger.Errorf("Failed to load CA certificate (%s): %s", caCertPath, err)
			return nil, err
		}

		caCert = string(caCertBytes)
	}

	director, err := getDirector(boshURL, creds, caCert, boshLogger)
	if err != nil {
		logger.Errorf("Could not reach BOSH Director (%s): %s", boshURL, err)
		return nil, err
	}

	deployment, err := director.FindDeployment(deploymentName)
	if err != nil {
		logger.Errorf("Failed to find deployment (%s): %s", deploymentName, err)
		return nil, err
	}

	vmInfos, err := deployment.VMInfos()
	if err != nil {
		logger.Errorf("Failed to list instances: %s", err)
		return nil, err
	}

	releases, err := deployment.Releases()
	if err != nil {
		logger.Errorf("Failed to list releases: %s", err)
		return nil, err
	}

	uuidgen := boshuuid.NewGenerator()

	sshOpts, privKey, err := boshdir.NewSSHOpts(uuidgen)
	if err != nil {
		logger.Errorf("Could not create SSH options: %s", err)
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey([]byte(privKey))
	if err != nil {
		logger.Errorf("Failed to parse SSH key: %s", err)
		return nil, err
	}

	return &boshDirector{
		vms:        vmInfos,
		releases:   releases,
		sshOpts:    sshOpts,
		deployment: deployment,
		signer:     signer,
		logger:     logger,
	}, nil
}

type boshDirector struct {
	vms     []boshdir.VMInfo
	sshOpts boshdir.SSHOpts

	releases []boshdir.Release

	signer ssh.Signer

	deployment boshdir.Deployment

	logger scanlog.Logger
}

func (d *boshDirector) VMs() []boshdir.VMInfo {
	return d.vms
}

func (d *boshDirector) Releases() []boshdir.Release {
	return d.releases
}

func (d *boshDirector) Cleanup() error {
	slug := boshdir.NewAllOrInstanceGroupOrInstanceSlug("", "")
	err := d.deployment.CleanUpSSH(slug, d.sshOpts)
	if err != nil {
		d.logger.Errorf("Failed to cleanup SSH session: %s", err)
	}

	return err
}

func (d *boshDirector) Setup() error {
	slug := boshdir.NewAllOrInstanceGroupOrInstanceSlug("", "")

	_, err := d.deployment.SetUpSSH(slug, d.sshOpts)
	if err != nil {
		d.logger.Errorf("Failed to set up SSH session: %s", err)
		return err
	}

	return nil
}

func (d *boshDirector) ConnectTo(logger scanlog.Logger, vm boshdir.VMInfo) remotemachine.RemoteMachine {
	return remotemachine.NewRemoteMachine(scantron.Machine{
		Address:  BestAddress(vm.IPs),
		Username: d.sshOpts.Username,
		Key:      d.signer,
	})
}

func getDirector(
	boshURL string,
	creds boshconfig.Creds,
	caCert string,
	logger boshlog.Logger,
) (boshdir.Director, error) {
	dirConfig, err := boshdir.NewConfigFromURL(boshURL)
	if err != nil {
		return nil, err
	}

	dirConfig.CACert = caCert

	directorInfo, err := getDirectorInfo(logger, dirConfig)
	if err != nil {
		return nil, err
	}

	if directorInfo.Auth.Type != "uaa" {
		dirConfig.Client = creds.Client
		dirConfig.ClientSecret = creds.ClientSecret
	} else if creds.IsUAA() {
		uaa, err := getUAA(dirConfig, creds, caCert, logger)
		if err != nil {
			return nil, err
		}

		if creds.IsUAAClient() {
			dirConfig.TokenFunc = boshuaa.NewClientTokenSession(uaa).TokenFunc
		} else {
			origToken := uaa.NewStaleAccessToken(creds.RefreshToken)
			dirConfig.TokenFunc = boshuaa.NewAccessTokenSession(origToken).TokenFunc
		}
	}

	director, err := boshdir.NewFactory(logger).New(dirConfig, boshdir.NewNoopTaskReporter(), boshdir.NewNoopFileReporter())
	if err != nil {
		return nil, err
	}

	return director, nil
}

func getUAA(dirConfig boshdir.Config, creds boshconfig.Creds, caCert string, logger boshlog.Logger) (boshuaa.UAA, error) {
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

	uaaConfig.CACert = caCert

	uaaConfig.Client = creds.Client
	uaaConfig.ClientSecret = creds.ClientSecret

	return boshuaa.NewFactory(logger).New(uaaConfig)
}

func getDirectorInfo(logger boshlog.Logger, dirConfig boshdir.Config) (boshdir.Info, error) {
	anonymousDirector, err := boshdir.NewFactory(logger).New(dirConfig, nil, nil)
	if err != nil {
		return boshdir.Info{}, err
	}

	directorInfo, err := anonymousDirector.Info()
	if err != nil {
		return boshdir.Info{}, err
	}

	return directorInfo, nil
}

func BestAddress(addresses []string) string {
	if len(addresses) == 0 {
		panic("BestAddress: candidate list is empty")
	}

	for _, addr := range addresses {
		if ip := net.ParseIP(addr).To4(); ip != nil {
			if ip[0] == 10 {
				return addr
			}
		}
	}

	return addresses[0]
}
