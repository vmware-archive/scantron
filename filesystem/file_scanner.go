package filesystem

import (
	"os"

	"path/filepath"

	"github.com/pivotal-cf/scantron"
)

func ScanFilesystem(rootPath string, excludedPaths []string) ([]scantron.File, error) {
	files := []scantron.File{}

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			for _, excludedPath := range excludedPaths {
				if excludedPath == path {
					return filepath.SkipDir
				}
			}

			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		// File has world read, write or execute permission
		if info.Mode()&07 > 0 {
			files = append(files, scantron.File{
				Path: path,
			})
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
