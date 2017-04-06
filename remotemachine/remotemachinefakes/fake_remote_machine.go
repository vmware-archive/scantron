// This file was generated by counterfeiter
package remotemachinefakes

import (
	"io"
	"sync"

	"github.com/pivotal-cf/scantron/remotemachine"
)

type FakeRemoteMachine struct {
	AddressStub        func() string
	addressMutex       sync.RWMutex
	addressArgsForCall []struct{}
	addressReturns     struct {
		result1 string
	}
	addressReturnsOnCall map[int]struct {
		result1 string
	}
	UploadFileStub        func(localPath, remotePath string) error
	uploadFileMutex       sync.RWMutex
	uploadFileArgsForCall []struct {
		localPath  string
		remotePath string
	}
	uploadFileReturns struct {
		result1 error
	}
	uploadFileReturnsOnCall map[int]struct {
		result1 error
	}
	DeleteFileStub        func(remotePath string) error
	deleteFileMutex       sync.RWMutex
	deleteFileArgsForCall []struct {
		remotePath string
	}
	deleteFileReturns struct {
		result1 error
	}
	deleteFileReturnsOnCall map[int]struct {
		result1 error
	}
	RunCommandStub        func(string) (io.Reader, error)
	runCommandMutex       sync.RWMutex
	runCommandArgsForCall []struct {
		arg1 string
	}
	runCommandReturns struct {
		result1 io.Reader
		result2 error
	}
	runCommandReturnsOnCall map[int]struct {
		result1 io.Reader
		result2 error
	}
	CloseStub        func() error
	closeMutex       sync.RWMutex
	closeArgsForCall []struct{}
	closeReturns     struct {
		result1 error
	}
	closeReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeRemoteMachine) Address() string {
	fake.addressMutex.Lock()
	ret, specificReturn := fake.addressReturnsOnCall[len(fake.addressArgsForCall)]
	fake.addressArgsForCall = append(fake.addressArgsForCall, struct{}{})
	fake.recordInvocation("Address", []interface{}{})
	fake.addressMutex.Unlock()
	if fake.AddressStub != nil {
		return fake.AddressStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.addressReturns.result1
}

func (fake *FakeRemoteMachine) AddressCallCount() int {
	fake.addressMutex.RLock()
	defer fake.addressMutex.RUnlock()
	return len(fake.addressArgsForCall)
}

func (fake *FakeRemoteMachine) AddressReturns(result1 string) {
	fake.AddressStub = nil
	fake.addressReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeRemoteMachine) AddressReturnsOnCall(i int, result1 string) {
	fake.AddressStub = nil
	if fake.addressReturnsOnCall == nil {
		fake.addressReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.addressReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *FakeRemoteMachine) UploadFile(localPath string, remotePath string) error {
	fake.uploadFileMutex.Lock()
	ret, specificReturn := fake.uploadFileReturnsOnCall[len(fake.uploadFileArgsForCall)]
	fake.uploadFileArgsForCall = append(fake.uploadFileArgsForCall, struct {
		localPath  string
		remotePath string
	}{localPath, remotePath})
	fake.recordInvocation("UploadFile", []interface{}{localPath, remotePath})
	fake.uploadFileMutex.Unlock()
	if fake.UploadFileStub != nil {
		return fake.UploadFileStub(localPath, remotePath)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.uploadFileReturns.result1
}

func (fake *FakeRemoteMachine) UploadFileCallCount() int {
	fake.uploadFileMutex.RLock()
	defer fake.uploadFileMutex.RUnlock()
	return len(fake.uploadFileArgsForCall)
}

func (fake *FakeRemoteMachine) UploadFileArgsForCall(i int) (string, string) {
	fake.uploadFileMutex.RLock()
	defer fake.uploadFileMutex.RUnlock()
	return fake.uploadFileArgsForCall[i].localPath, fake.uploadFileArgsForCall[i].remotePath
}

func (fake *FakeRemoteMachine) UploadFileReturns(result1 error) {
	fake.UploadFileStub = nil
	fake.uploadFileReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRemoteMachine) UploadFileReturnsOnCall(i int, result1 error) {
	fake.UploadFileStub = nil
	if fake.uploadFileReturnsOnCall == nil {
		fake.uploadFileReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.uploadFileReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRemoteMachine) DeleteFile(remotePath string) error {
	fake.deleteFileMutex.Lock()
	ret, specificReturn := fake.deleteFileReturnsOnCall[len(fake.deleteFileArgsForCall)]
	fake.deleteFileArgsForCall = append(fake.deleteFileArgsForCall, struct {
		remotePath string
	}{remotePath})
	fake.recordInvocation("DeleteFile", []interface{}{remotePath})
	fake.deleteFileMutex.Unlock()
	if fake.DeleteFileStub != nil {
		return fake.DeleteFileStub(remotePath)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.deleteFileReturns.result1
}

func (fake *FakeRemoteMachine) DeleteFileCallCount() int {
	fake.deleteFileMutex.RLock()
	defer fake.deleteFileMutex.RUnlock()
	return len(fake.deleteFileArgsForCall)
}

func (fake *FakeRemoteMachine) DeleteFileArgsForCall(i int) string {
	fake.deleteFileMutex.RLock()
	defer fake.deleteFileMutex.RUnlock()
	return fake.deleteFileArgsForCall[i].remotePath
}

func (fake *FakeRemoteMachine) DeleteFileReturns(result1 error) {
	fake.DeleteFileStub = nil
	fake.deleteFileReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRemoteMachine) DeleteFileReturnsOnCall(i int, result1 error) {
	fake.DeleteFileStub = nil
	if fake.deleteFileReturnsOnCall == nil {
		fake.deleteFileReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.deleteFileReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRemoteMachine) RunCommand(arg1 string) (io.Reader, error) {
	fake.runCommandMutex.Lock()
	ret, specificReturn := fake.runCommandReturnsOnCall[len(fake.runCommandArgsForCall)]
	fake.runCommandArgsForCall = append(fake.runCommandArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("RunCommand", []interface{}{arg1})
	fake.runCommandMutex.Unlock()
	if fake.RunCommandStub != nil {
		return fake.RunCommandStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.runCommandReturns.result1, fake.runCommandReturns.result2
}

func (fake *FakeRemoteMachine) RunCommandCallCount() int {
	fake.runCommandMutex.RLock()
	defer fake.runCommandMutex.RUnlock()
	return len(fake.runCommandArgsForCall)
}

func (fake *FakeRemoteMachine) RunCommandArgsForCall(i int) string {
	fake.runCommandMutex.RLock()
	defer fake.runCommandMutex.RUnlock()
	return fake.runCommandArgsForCall[i].arg1
}

func (fake *FakeRemoteMachine) RunCommandReturns(result1 io.Reader, result2 error) {
	fake.RunCommandStub = nil
	fake.runCommandReturns = struct {
		result1 io.Reader
		result2 error
	}{result1, result2}
}

func (fake *FakeRemoteMachine) RunCommandReturnsOnCall(i int, result1 io.Reader, result2 error) {
	fake.RunCommandStub = nil
	if fake.runCommandReturnsOnCall == nil {
		fake.runCommandReturnsOnCall = make(map[int]struct {
			result1 io.Reader
			result2 error
		})
	}
	fake.runCommandReturnsOnCall[i] = struct {
		result1 io.Reader
		result2 error
	}{result1, result2}
}

func (fake *FakeRemoteMachine) Close() error {
	fake.closeMutex.Lock()
	ret, specificReturn := fake.closeReturnsOnCall[len(fake.closeArgsForCall)]
	fake.closeArgsForCall = append(fake.closeArgsForCall, struct{}{})
	fake.recordInvocation("Close", []interface{}{})
	fake.closeMutex.Unlock()
	if fake.CloseStub != nil {
		return fake.CloseStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.closeReturns.result1
}

func (fake *FakeRemoteMachine) CloseCallCount() int {
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	return len(fake.closeArgsForCall)
}

func (fake *FakeRemoteMachine) CloseReturns(result1 error) {
	fake.CloseStub = nil
	fake.closeReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRemoteMachine) CloseReturnsOnCall(i int, result1 error) {
	fake.CloseStub = nil
	if fake.closeReturnsOnCall == nil {
		fake.closeReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.closeReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRemoteMachine) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.addressMutex.RLock()
	defer fake.addressMutex.RUnlock()
	fake.uploadFileMutex.RLock()
	defer fake.uploadFileMutex.RUnlock()
	fake.deleteFileMutex.RLock()
	defer fake.deleteFileMutex.RUnlock()
	fake.runCommandMutex.RLock()
	defer fake.runCommandMutex.RUnlock()
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeRemoteMachine) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ remotemachine.RemoteMachine = new(FakeRemoteMachine)
