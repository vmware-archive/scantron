package remotemachine

import (
	"bytes"
	"io"
	"sync"

	boshssh "github.com/cloudfoundry/bosh-init/ssh"
)

type MemWriter struct {
	instances map[string]*memWriterInstance
	lock      *sync.RWMutex
}

func NewMemWriter() *MemWriter {
	return &MemWriter{
		instances: map[string]*memWriterInstance{},
		lock:      &sync.RWMutex{},
	}
}

func (w *MemWriter) ForInstance(jobName, indexOrID, host string) boshssh.InstanceWriter {
	w.lock.Lock()
	defer w.lock.Unlock()

	instance := &memWriterInstance{
		jobName:   jobName,
		indexOrID: indexOrID,
		host:      host,

		stdout: bytes.NewBufferString(""),
		stderr: bytes.NewBufferString(""),
	}
	w.instances[host] = instance
	return instance
}

func (w *MemWriter) Flush() {}

func (w *MemWriter) ResultsForHost(host string) *memWriterInstance {
	w.lock.RLock()
	defer w.lock.RUnlock()

	if instance, ok := w.instances[host]; ok {
		return instance
	}
	return nil
}

type memWriterInstance struct {
	jobName   string
	indexOrID string
	host      string

	stdout *bytes.Buffer
	stderr *bytes.Buffer

	exitStatus int
	err        error
}

func (w *memWriterInstance) Stdout() io.Writer { return w.stdout }
func (w *memWriterInstance) Stderr() io.Writer { return w.stderr }
func (w *memWriterInstance) End(exitStatus int, err error) {
	w.exitStatus = exitStatus
	w.err = err
}

func (w *memWriterInstance) JobName() string         { return w.jobName }
func (w *memWriterInstance) IndexOrID() string       { return w.indexOrID }
func (w *memWriterInstance) Host() string            { return w.host }
func (w *memWriterInstance) StdoutReader() io.Reader { return w.stdout }
func (w *memWriterInstance) StdoutString() string    { return w.stdout.String() }
func (w *memWriterInstance) StderrReader() io.Reader { return w.stderr }
func (w *memWriterInstance) StderrString() string    { return w.stderr.String() }
func (w *memWriterInstance) ExitStatus() int         { return w.exitStatus }
func (w *memWriterInstance) Error() error            { return w.err }
