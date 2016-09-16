package remotemachine

import "io"

//go:generate counterfeiter . RemoteMachine

type RemoteMachine interface {
	Address() string

	UploadFile(localPath, remotePath string) error
	DeleteFile(remotePath string) error

	RunCommand(string) (io.Reader, error)

	Close() error
}
