//+build !windows

package filesystem

import (
	"github.com/pivotal-cf/scantron"
)

func ScanFiles() ([]scantron.File, error) {
	excludedPaths := []string{
		"/dev", "/proc", "/sys", "/run",
	}

	return ScanFilesystem("/", excludedPaths)
}