package remotemachine

import (
	"io/ioutil"
	"net"

	"golang.org/x/crypto/ssh"

	boshconfig "github.com/cloudfoundry/bosh-cli/cmd/config"
	boshdir "github.com/cloudfoundry/bosh-cli/director"
	boshuaa "github.com/cloudfoundry/bosh-cli/uaa"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	boshuuid "github.com/cloudfoundry/bosh-utils/uuid"

	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
)

//go:generate counterfeiter . BoshDirector

type BoshDirector interface {
	VMs() []boshdir.VMInfo
	ConnectTo(scanlog.Logger, boshdir.VMInfo) RemoteMachine

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
			logger.Errorf("failed-to-load-ca-certificate", err)
			return nil, err
		}

		caCert = string(caCertBytes)
	}

	director, err := getDirector(boshURL, creds, caCert, boshLogger)
	if err != nil {
		logger.Errorf("failed-to-get-director", err)
		return nil, err
	}

	deployment, err := director.FindDeployment(deploymentName)
	if err != nil {
		logger.Errorf("failed-to-find-deployment", err)
		return nil, err
	}

	vmInfos, err := deployment.VMInfos()
	if err != nil {
		logger.Errorf("failed-to-get-vm-infos", err)
		return nil, err
	}

	uuidgen := boshuuid.NewGenerator()

	sshOpts, privKey, err := boshdir.NewSSHOpts(uuidgen)
	if err != nil {
		logger.Errorf("failed-to-create-ssh-opts", err)
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey([]byte(privKey))
	if err != nil {
		logger.Errorf("failed-to-parse-ssh-key", err)
		return nil, err
	}

	return &boshDirector{
		vms:        vmInfos,
		sshOpts:    sshOpts,
		deployment: deployment,
		signer:     signer,
		logger:     logger,
	}, nil
}

type boshDirector struct {
	vms     []boshdir.VMInfo
	sshOpts boshdir.SSHOpts

	signer ssh.Signer

	deployment boshdir.Deployment

	logger scanlog.Logger
}

func (d *boshDirector) VMs() []boshdir.VMInfo {
	return d.vms
}

func (d *boshDirector) Cleanup() error {
	slug := boshdir.NewAllOrInstanceGroupOrInstanceSlug("", "")
	err := d.deployment.CleanUpSSH(slug, d.sshOpts)
	if err != nil {
		d.logger.Errorf("failed-to-clean-up-ssh", err)
	}

	return err
}

func (d *boshDirector) Setup() error {
	slug := boshdir.NewAllOrInstanceGroupOrInstanceSlug("", "")

	_, err := d.deployment.SetUpSSH(slug, d.sshOpts)
	if err != nil {
		d.logger.Errorf("failed-to-set-up-ssh", err)
		return err
	}

	return nil
}

func (d *boshDirector) ConnectTo(logger scanlog.Logger, vm boshdir.VMInfo) RemoteMachine {
	return NewSimple(scantron.Machine{
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
