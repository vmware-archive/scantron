package remotemachine

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"

	"code.cloudfoundry.org/lager"

	boshcmd "github.com/cloudfoundry/bosh-init/cmd"
	boshconfig "github.com/cloudfoundry/bosh-init/cmd/config"
	boshdir "github.com/cloudfoundry/bosh-init/director"
	boshssh "github.com/cloudfoundry/bosh-init/ssh"
	boshuaa "github.com/cloudfoundry/bosh-init/uaa"
	boshui "github.com/cloudfoundry/bosh-init/ui"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
)

//go:generate counterfeiter . BoshDirector

type BoshDirector interface {
	VMs() []boshdir.VMInfo
	ConnectTo(lager.Logger, boshdir.VMInfo) RemoteMachine

	Cleanup() error
}

func NewBoshDirector(
	logger lager.Logger,
	creds boshconfig.Creds,
	deploymentName string,
	boshURL string,
	boshUsername string,
	boshPassword string,
	boshLogger boshlog.Logger,
	gatewayUsername string,
	gatewayHost string,
	gatewayPrivateKeyPath string,
) (BoshDirector, error) {
	director, err := getDirector(boshURL, boshUsername, boshPassword, creds, boshLogger)
	if err != nil {
		logger.Error("failed-to-get-director", err)
		return nil, err
	}

	deployment, err := director.FindDeployment(deploymentName)
	if err != nil {
		logger.Error("failed-to-find-deployment", err)
		return nil, err
	}

	vmInfos, err := deployment.VMInfos()
	if err != nil {
		logger.Error("failed-to-get-vm-infos", err)
		return nil, err
	}

	ui := boshui.NewConfUI(boshLogger)
	deps := boshcmd.NewBasicDeps(ui, boshLogger)

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

	err = deps.FS.ChangeTempRoot(tmpDirPath)
	if err != nil {
		logger.Error("failed-to-change-temp-root", err)
		return nil, err
	}

	sshSessionFactory := func(o boshssh.ConnectionOpts, r boshdir.SSHResult) boshssh.Session {
		return boshssh.NewSessionImpl(o, boshssh.SessionImplOpts{ForceTTY: true}, r, deps.FS)
	}

	sshWriter := NewMemWriter()

	comboRunner := boshssh.NewComboRunner(
		deps.CmdRunner,
		sshSessionFactory,
		signal.Notify,
		sshWriter,
		deps.FS,
		ui,
		boshLogger,
	)

	sshRunner := boshssh.NewNonInteractiveRunner(comboRunner)

	scpSessionFactory := func(o boshssh.ConnectionOpts, r boshdir.SSHResult) boshssh.Session {
		return boshssh.NewSessionImpl(o, boshssh.SessionImplOpts{ForceTTY: false}, r, deps.FS)
	}

	scpWriter := NewMemWriter()

	scpComboRunner := boshssh.NewComboRunner(
		deps.CmdRunner,
		scpSessionFactory,
		signal.Notify,
		scpWriter,
		deps.FS,
		ui,
		boshLogger,
	)

	scpRunner := boshssh.NewSCPRunner(scpComboRunner)

	sshOpts, privKey, err := boshdir.NewSSHOpts(deps.UUIDGen)
	if err != nil {
		logger.Error("failed-to-create-ssh-opts", err)
		return nil, err
	}

	return &boshDirector{
		vms:                   vmInfos,
		sshRunner:             sshRunner,
		sshWriter:             sshWriter,
		scpRunner:             scpRunner,
		sshOpts:               sshOpts,
		privKey:               privKey,
		deployment:            deployment,
		gatewayUsername:       gatewayUsername,
		gatewayHost:           gatewayHost,
		gatewayPrivateKeyPath: gatewayPrivateKeyPath,
		tmpdir:                tmpDirPath,
	}, nil
}

type boshDirector struct {
	vms       []boshdir.VMInfo
	sshRunner boshssh.NonInteractiveRunner
	sshWriter *MemWriter
	scpRunner boshssh.SCPRunnerImpl
	sshOpts   boshdir.SSHOpts
	privKey   string

	deployment boshdir.Deployment

	gatewayUsername       string
	gatewayHost           string
	gatewayPrivateKeyPath string

	tmpdir string
}

func (d *boshDirector) VMs() []boshdir.VMInfo {
	return d.vms
}

func (d *boshDirector) Cleanup() error {
	return os.RemoveAll(d.tmpdir)
}

func (d *boshDirector) ConnectTo(logger lager.Logger, vm boshdir.VMInfo) RemoteMachine {
	slug := boshdir.NewAllOrPoolOrInstanceSlug(vm.JobName, vm.ID)

	sshResult, err := d.deployment.SetUpSSH(slug, d.sshOpts)

	if err != nil {
		logger.Error("failed-to-set-up-ssh", err)
		return nil
	}

	connOpts := boshssh.ConnectionOpts{
		PrivateKey: d.privKey,

		GatewayUsername:       d.gatewayUsername,
		GatewayHost:           d.gatewayHost,
		GatewayPrivateKeyPath: d.gatewayPrivateKeyPath,
	}

	return &boshMachine{
		vmInfo:     vm,
		connOpts:   connOpts,
		sshResult:  sshResult,
		sshRunner:  d.sshRunner,
		scpRunner:  d.scpRunner,
		sshWriter:  d.sshWriter,
		deployment: d.deployment,
	}
}

type boshMachine struct {
	vmInfo     boshdir.VMInfo
	connOpts   boshssh.ConnectionOpts
	sshResult  boshdir.SSHResult
	sshRunner  boshssh.NonInteractiveRunner
	scpRunner  boshssh.SCPRunnerImpl
	sshWriter  *MemWriter
	deployment boshdir.Deployment

	sshOpts boshdir.SSHOpts
	slug    boshdir.AllOrPoolOrInstanceSlug
}

func (b *boshMachine) Address() string {
	return b.vmInfo.IPs[0]
}

func (b *boshMachine) UploadFile(localPath string, remotePath string) error {
	scpArgs := boshssh.NewSCPArgs(
		[]string{localPath, fmt.Sprintf("%s/%d:%s", b.vmInfo.JobName, *b.vmInfo.Index, remotePath)}, false)

	return b.scpRunner.Run(b.connOpts, b.sshResult, scpArgs)
}

func (b *boshMachine) DeleteFile(remotePath string) error {
	return b.sshRunner.Run(b.connOpts, b.sshResult, []string{"sudo", "rm", remotePath, "-f"})
}

func (b *boshMachine) RunCommand(cmd string) (io.Reader, error) {
	err := b.sshRunner.Run(b.connOpts, b.sshResult, append([]string{"sudo"}, strings.Split(cmd, " ")...))
	if err != nil {
		result := b.sshWriter.ResultsForHost(b.Address())
		fmt.Println(result.StdoutString())
		return nil, err
	}

	result := b.sshWriter.ResultsForHost(b.Address())
	if result == nil {
		return strings.NewReader(""), nil
	}

	return result.StdoutReader(), nil
}

func (b *boshMachine) Close() error {
	return b.deployment.CleanUpSSH(b.slug, b.sshOpts)
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
