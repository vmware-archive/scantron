//+build windows

package filesystem

import (
	"fmt"
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
	"os"
)

type metadata struct {
}

func GetFileMetadata() FileMetadata {
	return &metadata{}
}

func GetFileConfig() FileConfig {
	return FileConfig{
		RootPath:      "C:\\",
		ExcludedPaths: []string{},
	}
}

func (f *metadata) GetUser(path string, fileInfo os.FileInfo) (string, error) {
	ownerSid, _, err := f.getSids(path, fileInfo)
	if err != nil {
		return "", err
	}
	return f.lookupSid(ownerSid)
}

func (f *metadata) GetGroup(path string, fileInfo os.FileInfo) (string, error) {
	_, groupSid, err := f.getSids(path, fileInfo)
	if err != nil {
		return "", err
	}
	return f.lookupSid(groupSid)
}

func (f *metadata) getSids(path string, fileInfo os.FileInfo) (*windows.SID, *windows.SID, error) {
	var (
		owner *windows.SID
		group *windows.SID
	)
	err := api.GetNamedSecurityInfo(
		fmt.Sprintf("\\\\?\\%s", path), // prefix \\?\ to enable extended-length paths > 260 characters
		api.SE_FILE_OBJECT,
		api.OWNER_SECURITY_INFORMATION|api.GROUP_SECURITY_INFORMATION,
		&owner,
		&group,
		nil,
		nil,
		nil,
	)

	if err != nil {
		return nil, nil, err
	}

	return owner, group, nil
}

func (f *metadata) lookupSid(sid *windows.SID) (string, error) {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		sidString, err := sid.String()
		if err != nil {
			return "", err
		}
		return sidString, nil
	}
	return fmt.Sprintf("%s\\%s", domain, account), nil
}
