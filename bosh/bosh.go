package bosh

import (
	"bufio"
	"io/ioutil"
	"net"
	"os"

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

type TargetDeployment interface {
	Name() string
	VMs() []boshdir.VMInfo
	Releases() []boshdir.Release

	Setup() error
	ConnectTo(boshdir.VMInfo) remotemachine.RemoteMachine
	Cleanup() error
}

type TargetDeploymentImpl struct {
	sshOpts    boshdir.SSHOpts
	signer     ssh.Signer
	deployment boshdir.Deployment
	logger     scanlog.Logger
}

type Stuff interface {
	GetDeployments(
	 	boshconfig.Creds,
	 	string,
	 	[]string,
	 	string,
	 	scanlog.Logger) ([]TargetDeployment, error)
}

type StuffImpl struct{

}

func(s *StuffImpl)  GetDeployments(
	creds boshconfig.Creds,
	caCertPath string,
	deploymentNames []string,
	boshURL string,
	logger scanlog.Logger) ([]TargetDeployment, error) {

	var caCert string

	if caCertPath != "" {
		caCertBytes, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			logger.Errorf("Failed to load CA certificate (%s): %s", caCertPath, err)
			return nil, err
		}

		caCert = string(caCertBytes)
	}

	out := bufio.NewWriter(os.Stdout)
	boshLogger := boshlog.NewWriterLogger(boshlog.LevelNone, out)
	director, err := getDirector(boshURL, creds, caCert, boshLogger)
	if err != nil {
		logger.Errorf("Could not reach BOSH Director (%s): %s", boshURL, err)
		return nil, err
	}

	deps := []TargetDeployment{}
	uuidgen := boshuuid.NewGenerator()
	for _, depName := range deploymentNames {

		sshOpts, privKey, err := boshdir.NewSSHOpts(uuidgen)
		if err != nil {
			logger.Errorf("Could not create SSH options: %s", err)
			return nil, err
		}
		logger.Debugf("Generated user %s for deployment %s", sshOpts.Username, depName)

		signer, err := ssh.ParsePrivateKey([]byte(privKey))
		if err != nil {
			logger.Errorf("Failed to parse SSH key: %s", err)
			return nil, err
		}

		deployment, err := director.FindDeployment(depName)
		if err != nil {
			logger.Errorf("Failed to find deployment (%s): %s", depName, err)
			return nil, err
		}
		logger.Debugf("Found deployment %s", deployment.Name())
		deps = append(deps, &TargetDeploymentImpl{
			sshOpts:    sshOpts,
			signer:     signer,
			deployment: deployment,
			logger:     logger,
		})
	}

	for _, d := range deps {
		logger.Debugf("Generated Target deployment %s", d.Name())
	}

	return deps, nil
}

func (d *TargetDeploymentImpl) Name() string {
	return d.deployment.Name()
}

func (d *TargetDeploymentImpl) VMs() []boshdir.VMInfo {
	vms, _ := d.deployment.VMInfos()
	return vms
}

func (d *TargetDeploymentImpl) Releases() []boshdir.Release {
	releases, _ := d.deployment.Releases()
	return releases
}

func (d *TargetDeploymentImpl) Setup() error {
	d.logger.Debugf("About to setup SSH for deployment %s", d.Name())
	slug := boshdir.NewAllOrInstanceGroupOrInstanceSlug("", "")

	_, err := d.deployment.SetUpSSH(slug, d.sshOpts)
	if err != nil {
		return err
	}

	return nil
}

func (d *TargetDeploymentImpl) ConnectTo(vm boshdir.VMInfo) remotemachine.RemoteMachine {
	stemcells, _ := d.deployment.Stemcells()
	return remotemachine.NewRemoteMachine(scantron.Machine{
		Address:  BestAddress(vm.IPs),
		Username: d.sshOpts.Username,
		Key:      d.signer,
		OSName:   stemcells[0].Name(),
	})
}

func (d *TargetDeploymentImpl) Cleanup() error {
	d.logger.Debugf("About to cleanup SSH for deployment %s", d.Name())
	slug := boshdir.NewAllOrInstanceGroupOrInstanceSlug("", "")
	err := d.deployment.CleanUpSSH(slug, d.sshOpts)
	return err
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

func getUAA(dirConfig boshdir.FactoryConfig, creds boshconfig.Creds, caCert string, logger boshlog.Logger) (boshuaa.UAA, error) {
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

func getDirectorInfo(logger boshlog.Logger, dirConfig boshdir.FactoryConfig) (boshdir.Info, error) {
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
