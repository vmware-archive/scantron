package remotemachine

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/pivotal-cf/scantron"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

//go:generate counterfeiter . RemoteMachine

type RemoteMachine interface {
	Address() string

	UploadFile(localPath, remotePath string) error
	DeleteFile(remotePath string) error

	RunCommand(string) (io.Reader, error)

	Close() error
}

type remoteMachine struct {
	machine scantron.Machine

	conn *ssh.Client
}

func NewRemoteMachine(machine scantron.Machine) RemoteMachine {
	return &remoteMachine{
		machine: machine,
	}
}

func (r *remoteMachine) Address() string {
	return fmt.Sprintf("%s:22", r.machine.Address)
}

func (r *remoteMachine) UploadFile(localPath, remotePath string) error {
	conn, err := r.sshConn()
	if err != nil {
		return err
	}

	sftp, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer sftp.Close()

	srcFile, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := sftp.Create(remotePath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	dstFile.ReadFrom(srcFile)
	sftp.Chmod(remotePath, 0700)

	return nil
}

func (r *remoteMachine) DeleteFile(remotePath string) error {
	conn, err := r.sshConn()
	if err != nil {
		return err
	}

	sftp, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer sftp.Close()

	return sftp.Remove(remotePath)
}

func (r *remoteMachine) RunCommand(command string) (io.Reader, error) {
	conn, err := r.sshConn()
	if err != nil {
		return nil, err
	}

	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}

	bs, err := session.Output(fmt.Sprintf("echo %s | sudo -S -- %s", r.machine.Password, command))
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(bs), nil
}

func (r *remoteMachine) auth() []ssh.AuthMethod {
	if r.machine.Key != nil {
		return []ssh.AuthMethod{
			ssh.PublicKeys(r.machine.Key),
		}
	}

	return []ssh.AuthMethod{
		ssh.Password(r.machine.Password),
	}
}

func (r *remoteMachine) sshConn() (*ssh.Client, error) {
	if r.conn != nil {
		return r.conn, nil
	}

	config := &ssh.ClientConfig{
		User:            r.machine.Username,
		Auth:            r.auth(),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", r.Address(), config)
	if err != nil {
		return nil, err
	}

	r.conn = conn

	return conn, nil
}

func (r *remoteMachine) Close() error {
	if r.conn != nil {
		return r.conn.Close()
	}

	return nil
}
