package tlsscan

import (
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
)

type TlsScanner interface {
	Scan(logger scanlog.Logger, host string, port string) (scantron.CipherInformation, error)
	FetchTLSInformation(host, port string) (*scantron.Certificate, bool, error)
}
