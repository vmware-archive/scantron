package filesystem

import (
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
	"os"
)

type FileMetadata interface {
	GetUser(path string, fileInfo os.FileInfo) (string, error)
	GetGroup(path string, fileInfo os.FileInfo) (string, error)
}

type FileScanner struct {
	Walker   FileWalker
	Metadata FileMetadata
	Logger   scanlog.Logger
}

func (fs *FileScanner) ScanFiles() ([]scantron.File, error) {

	walkedFiles, err := fs.Walker.Walk()
	if err != nil {
		return nil, err
	}

	files := []scantron.File{}
	for _, wf := range walkedFiles {
		user, err := fs.Metadata.GetUser(wf.Path, wf.Info)

		// Some files (e.g. C:\pagefile.sys) don't have user/group
		if err != nil {
			fs.Logger.Warnf("Error retrieving user for %s: %s", wf.Path, err)
		}
		group, err := fs.Metadata.GetGroup(wf.Path, wf.Info)
		if err != nil {
			fs.Logger.Warnf("Error retrieving group for %s: %s", wf.Path, err)
		}

		file := scantron.File{
			Path:         wf.Path,
			Permissions:  wf.Info.Mode(),
			Size:         wf.Info.Size(),
			User:         user,
			Group:        group,
			ModifiedTime: wf.Info.ModTime(),
			RegexMatches: wf.RegexMatches,
		}

		fs.Logger.Debugf("Record file %s: Permissions: '%d' User: '%s' Group: '%s' Size: '%d' Modified: '%s'",
			wf.Path, file.Permissions, file.User, file.Group, file.Size, file.ModifiedTime.String())

		files = append(files, file)
	}

	return files, nil
}
