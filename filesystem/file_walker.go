package filesystem

import (
	"bufio"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/scanlog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type WalkedFile struct {
	Path         string
	Info         os.FileInfo
	RegexMatches []scantron.RegexMatch
}

type FileConfig struct {
	ExcludedPaths []string
	RootPath      string
}

type FileWalker interface {
	Walk() ([]WalkedFile, error)
}

type fileWalker struct {
	config                 FileConfig
	logger                 scanlog.Logger
	compiledPathRegexes    []*regexp.Regexp
	compiledContentRegexes []*regexp.Regexp
	maxRegexFileSize       int64
}

type regexJob struct {
	wf           WalkedFile
	matchedPaths []string
}

func NewWalker(config FileConfig,
	fileMatch scantron.FileMatch,
	logger scanlog.Logger) (FileWalker, error) {

	compiledPathRegexes, err := compileRegexes(logger, fileMatch.PathRegexes)
	if err != nil {
		return nil, err
	}
	compiledContentRegexes, err := compileRegexes(logger, fileMatch.ContentRegexes)
	if err != nil {
		return nil, err
	}

	return &fileWalker{
		config:                 config,
		logger:                 logger,
		compiledPathRegexes:    compiledPathRegexes,
		compiledContentRegexes: compiledContentRegexes,
		maxRegexFileSize:       fileMatch.MaxRegexFileSize,
	}, nil
}

func compileRegexes(logger scanlog.Logger, regexes []string) ([]*regexp.Regexp, error) {
	compiledRegexes := []*regexp.Regexp{}

	for _, regex := range regexes {
		logger.Debugf("Compiling regex for %s", regex)
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return nil, err
		}

		compiledRegexes = append(compiledRegexes, compiled)
	}

	return compiledRegexes, nil
}

func (fw *fileWalker) Walk() ([]WalkedFile, error) {
	files := []WalkedFile{}
	done := make(chan error, 1)
	defer close(done)
	const (
		maxInFlight = 100
	)
	wf := make(chan WalkedFile, maxInFlight)
	regexQueue := make(chan regexJob, maxInFlight)
	wg := &sync.WaitGroup{}

	go func() {
		done <- filepath.Walk(fw.config.RootPath, func(path string, info os.FileInfo, err error) error {
			fw.logger.Debugf("Visiting file %s", path)
			if err != nil {
				fw.logger.Errorf("Error accessing %s: %s", path, err)
				return err
			}

			if info.IsDir() {
				for _, excludedPath := range fw.config.ExcludedPaths {
					if excludedPath == path {
						fw.logger.Infof("Skipping excluded directory %s", path)
						return filepath.SkipDir
					}
				}

				return nil
			}

			if !info.Mode().IsRegular() {
				fw.logger.Debugf("Skipping irregular file %s", path)
				return nil
			}

			matchedPathRegexes := fw.matchPath(path)
			pathMatch := len(fw.compiledPathRegexes) == 0 || len(matchedPathRegexes) > 0
			sizeMatch := info.Size() <= fw.maxRegexFileSize
			checkContent := pathMatch && sizeMatch && len(fw.compiledContentRegexes) > 0
			if pathMatch && !sizeMatch {
				fw.logger.Debugf("Skipping content scan for %s: file too large", path)
			}

			file := WalkedFile{
				Path:         path,
				Info:         info,
				RegexMatches: nil,
			}
			if checkContent {
				wg.Add(1)
				regexQueue <- regexJob{
					file,
					matchedPathRegexes,
				}
				fw.logger.Debugf("Queued file %s for content check", path)
			} else {
				wf <- file
				fw.logger.Debugf("Recorded file %s", path)
			}

			return nil
		})
	}()

	if len(fw.compiledContentRegexes) > 0 {
		for i := 0; i < maxInFlight; i++ {
			go func() {
				for job := range regexQueue {
					fw.logger.Debugf("Checking file %s", job.wf.Path)
					regexMatches, err := fw.matchContent(job.wf.Path, job.matchedPaths)
					if err != nil {
						fw.logger.Warnf("Error checking content of %s: %s", job.wf.Path, err)
					}

					job.wf.RegexMatches = regexMatches
					wf <- job.wf

					fw.logger.Debugf("Recorded file %s", job.wf.Path)
					wg.Done()
				}
			}()
		}
	}

	go func() {
		fw.logger.Debugf("Waiting for walker")
		err := <-done
		fw.logger.Debugf("Waiting for wait group")
		wg.Wait()
		fw.logger.Debugf("Done waiting for files")
		close(wf)
		close(regexQueue)
		done <- err
		fw.logger.Debugf("Walker result forwarded")
	}()

	for file := range wf {
		files = append(files, file)
	}
	fw.logger.Debugf("File scan results aggregated")

	err := <-done
	fw.logger.Debugf("Walker result received")
	if err != nil {
		fw.logger.Errorf("Error scanning files: %s", err)
		return nil, err
	}

	return files, nil
}

func (fw *fileWalker) matchPath(path string) []string {
	var matchedPathRegexes []string

	for _, pathRegex := range fw.compiledPathRegexes {
		if pathRegex.MatchString(path) {
			fw.logger.Debugf("File path %s matches %s", path, pathRegex.String())
			matchedPathRegexes = append(matchedPathRegexes, pathRegex.String())
		}
	}

	return matchedPathRegexes
}

func (fw *fileWalker) matchContent(path string, matchedPathRegexes []string) ([]scantron.RegexMatch, error) {
	var regexMatches []scantron.RegexMatch

	for _, contentRegex := range fw.compiledContentRegexes {
		match, err := fw.checkContent(contentRegex, path)
		if err != nil {
			return nil, err
		}
		if match {
			fw.logger.Debugf("Content of %s matches %s", path, contentRegex.String())
			if len(matchedPathRegexes) == 0 {
				regexMatches = append(regexMatches, scantron.RegexMatch{
					ContentRegex: contentRegex.String(),
					PathRegex:    "",
				})
			} else {
				for _, pr := range matchedPathRegexes {
					regexMatches = append(regexMatches, scantron.RegexMatch{
						ContentRegex: contentRegex.String(),
						PathRegex:    pr,
					})
				}
			}
		}
	}

	return regexMatches, nil
}

func (fw *fileWalker) checkContent(contentRegex *regexp.Regexp, path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	rr := bufio.NewReader(f)
	return contentRegex.MatchReader(rr), nil
}
