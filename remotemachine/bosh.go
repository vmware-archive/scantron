package remotemachine

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"code.cloudfoundry.org/lager"
	"github.com/pivotal-golang/clock"

	boshconfig "github.com/cloudfoundry/bosh-cli/cmd/config"
	bicrypto "github.com/cloudfoundry/bosh-cli/crypto"
	boshdir "github.com/cloudfoundry/bosh-cli/director"
	boshssh "github.com/cloudfoundry/bosh-cli/ssh"
	boshuaa "github.com/cloudfoundry/bosh-cli/uaa"
	boshui "github.com/cloudfoundry/bosh-cli/ui"
	boshcrypto "github.com/cloudfoundry/bosh-utils/crypto"
	boshfileutil "github.com/cloudfoundry/bosh-utils/fileutil"
	boshlog "github.com/cloudfoundry/bosh-utils/logger"
	boshsys "github.com/cloudfoundry/bosh-utils/system"
	boshuuid "github.com/cloudfoundry/bosh-utils/uuid"
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
	caCert string,
	deploymentName string,
	boshURL string,
	boshLogger boshlog.Logger,
	gatewayUsername string,
	gatewayHost string,
	gatewayPrivateKeyPath string,
) (BoshDirector, error) {
	director, err := getDirector(boshURL, creds, caCert, boshLogger)
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
	deps := NewBasicDeps(ui, boshLogger)

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
	slug := boshdir.NewAllOrInstanceGroupOrInstanceSlug(vm.JobName, vm.ID)

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
	slug    boshdir.AllOrInstanceGroupOrInstanceSlug
}

func (b *boshMachine) Address() string {
	return BestAddress(b.vmInfo.IPs)
}

func (b *boshMachine) Job() string {
	return b.vmInfo.JobName
}

func (b *boshMachine) IndexOrId() string {
	if len(b.vmInfo.ID) > 0 {
		return b.vmInfo.ID
	}

	if b.vmInfo.Index != nil {
		return strconv.Itoa(*b.vmInfo.Index)
	}

	return ""
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
		result := b.sshWriter.ResultsForInstance(b.Job(), b.IndexOrId())
		fmt.Println(result.StdoutString())
		return nil, err
	}

	result := b.sshWriter.ResultsForInstance(b.Job(), b.IndexOrId())
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
	creds boshconfig.Creds,
    caCert string,
	logger boshlog.Logger,
) (boshdir.Director, error) {
	dirConfig, err := boshdir.NewConfigFromURL(boshURL)
	if err != nil {
		return nil, err
	}

	certBytes, err := ioutil.ReadFile(caCert)
	if err != nil {
		panic(err)
	}

	dirConfig.CACert = string(certBytes)

	anonymousDirector, err := boshdir.NewFactory(logger).New(dirConfig, nil, nil)
	if err != nil {
		panic(err)
	}

	directorInfo, err := anonymousDirector.Info()
	if err != nil {
		panic(err)
	}

	if directorInfo.Auth.Type != "uaa" {
		dirConfig.Client = creds.Client
		dirConfig.ClientSecret = creds.ClientSecret
	} else if creds.IsUAA() {
		uaa, err := getUAA(dirConfig, creds, logger)
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

type BasicDeps struct {
	FS     boshsys.FileSystem
	UI     *boshui.ConfUI
	Logger boshlog.Logger

	UUIDGen                  boshuuid.Generator
	CmdRunner                boshsys.CmdRunner
	Compressor               boshfileutil.Compressor
	DigestCalculator         bicrypto.DigestCalculator
	DigestCreationAlgorithms []boshcrypto.Algorithm

	Time clock.Clock
}

func NewBasicDeps(ui *boshui.ConfUI, logger boshlog.Logger) BasicDeps {
	return NewBasicDepsWithFS(ui, boshsys.NewOsFileSystemWithStrictTempRoot(logger), logger)
}

func NewBasicDepsWithFS(ui *boshui.ConfUI, fs boshsys.FileSystem, logger boshlog.Logger) BasicDeps {
	cmdRunner := boshsys.NewExecCmdRunner(logger)

	digestCreationAlgorithms := []boshcrypto.Algorithm{boshcrypto.DigestAlgorithmSHA1}
	digestCalculator := bicrypto.NewDigestCalculator(fs, digestCreationAlgorithms)

	return BasicDeps{
		FS:     fs,
		UI:     ui,
		Logger: logger,

		UUIDGen:                  boshuuid.NewGenerator(),
		CmdRunner:                cmdRunner,
		Compressor:               boshfileutil.NewTarballCompressor(cmdRunner, fs),
		DigestCalculator:         digestCalculator,
		DigestCreationAlgorithms: digestCreationAlgorithms,
		Time: clock.NewClock(),
	}
}
