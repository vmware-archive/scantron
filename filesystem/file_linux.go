//+build !windows

package filesystem

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
)

type metadata struct {
}

func GetFileMetadata() (FileMetadata) {
	return &metadata{}
}

func GetFileConfig() (FileConfig) {
	return FileConfig {
		RootPath: "/",
		ExcludedPaths: []string{
			"/dev", "/proc", "/sys", "/run",
		},
	}
}

func (f *metadata) GetUser(_ string, fileInfo os.FileInfo) (string, error) {
	uid := fmt.Sprint(fileInfo.Sys().(*syscall.Stat_t).Uid)
	user, err := user.LookupId(uid)
	if err != nil {
		return uid, nil
	}
	return user.Username, nil
}

func (f *metadata) GetGroup(_ string, fileInfo os.FileInfo) (string, error) {
	gid := fmt.Sprint(fileInfo.Sys().(*syscall.Stat_t).Gid)
	group, err := user.LookupGroupId(gid)
	if err != nil {
		return gid, nil
	}
	return group.Name, nil
}