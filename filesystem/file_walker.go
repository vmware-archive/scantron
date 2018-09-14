package filesystem

import (
  "github.com/pivotal-cf/scantron/scanlog"
  "os"
  "path/filepath"
)

type WalkedFile struct {
  Path string
  Info os.FileInfo
}

type FileConfig struct {
  ExcludedPaths []string
  RootPath string
}

type FileWalker interface {
  Walk() ([]WalkedFile, error)
}

type fileWalker struct {
  config FileConfig
  logger scanlog.Logger
}

func NewWalker(config FileConfig, logger scanlog.Logger) (FileWalker) {
  return &fileWalker{
    config: config,
    logger: logger,
  }
}

func (fw *fileWalker) Walk() ([]WalkedFile, error) {
  files := []WalkedFile{}
  err := filepath.Walk(fw.config.RootPath, func(path string, info os.FileInfo, err error) error {
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

    files = append(files, WalkedFile{
      Path: path,
      Info: info,
    })

    fw.logger.Debugf("Record file %s", path)

    return nil
  })

  if err != nil {
    fw.logger.Errorf("Error scanning files: %s", err)
    return nil, err
  }

  return files, nil
}