package filesystem

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/pivotal-cf/scantron"
)

func ScanFilesystem(rootPath string, excludedPaths []string) []scantron.File {
	arguments := []string{rootPath}

	for _, path := range excludedPaths {
		arguments = append(arguments, "-path", path, "-prune", "-o")
	}

	if runtime.GOOS != "darwin" {
		arguments = append(arguments, "!", "-readable", "-prune", "-o")
	}

	arguments = append(arguments, "-type", "f")

	if runtime.GOOS == "darwin" {
		arguments = append(arguments, "-perm", "+007")
	} else {
		arguments = append(arguments, "-perm", "/007")
	}

	arguments = append(arguments, "-print")

	bs, err := exec.Command("find", arguments...).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: failed to get list of world-writable files:", err)
		os.Exit(1)
	}

	findLines := strings.Split(string(bs), "\n")

	files := []scantron.File{}

	for _, line := range findLines {
		if line != "" {
			files = append(files, scantron.File{
				Path: line,
			})
		}
	}

	return files
}
